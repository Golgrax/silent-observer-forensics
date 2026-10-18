package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"unicode"
)

type Chunk struct {
	Length uint32
	Type   string
	Offset int64
	Data   []byte
	CRC    uint32
}

func main() {
	filePath := flag.String("file", "absolute.png", "Path to the PNG file to analyze")
	dumpTrailing := flag.String("dump-trailing", "", "Output file path to save trailing data if detected")
	flag.Parse()

	fmt.Println("==========================================================")
	fmt.Printf("[*] PNG Forensics & Metadata Analyzer\n")
	fmt.Printf("[*] Target File: %s\n", *filePath)
	fmt.Println("==========================================================")

	fileData, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Total File Size: %d bytes (%.2f MB)\n", len(fileData), float64(len(fileData))/(1024*1024))

	// Verify PNG signature (89 50 4E 47 0D 0A 1A 0A)
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(fileData) < 8 || !bytes.Equal(fileData[:8], pngSig) {
		fmt.Println("[-] Error: Invalid PNG magic signature!")
		os.Exit(1)
	}
	fmt.Println("[+] PNG Signature Verified: 89 50 4E 47 0D 0A 1A 0A")

	reader := bytes.NewReader(fileData[8:])
	var chunks []Chunk
	var iendOffset int64 = -1
	var metadata = make(map[string]string)

	fmt.Println("\n[*] Parsing PNG Chunks:")
	for {
		currentOffset, _ := reader.Seek(0, io.SeekCurrent)
		realOffset := currentOffset + 8

		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			break
		}

		typeBytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, typeBytes); err != nil {
			break
		}
		chunkType := string(typeBytes)

		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			break
		}

		var crc uint32
		if err := binary.Read(reader, binary.BigEndian, &crc); err != nil {
			break
		}

		chunk := Chunk{
			Length: length,
			Type:   chunkType,
			Offset: realOffset,
			Data:   data,
			CRC:    crc,
		}
		chunks = append(chunks, chunk)

		if chunkType != "IDAT" {
			fmt.Printf("  -> Chunk [%s] at offset 0x%08X (Length: %d bytes, CRC: 0x%08X)\n", chunkType, realOffset, length, crc)
		}

		// Text metadata chunks (tEXt, zTXt, iTXt)
		if chunkType == "tEXt" || chunkType == "zTXt" || chunkType == "iTXt" {
			parts := bytes.SplitN(data, []byte{0}, 2)
			if len(parts) >= 2 {
				key := string(parts[0])
				val := string(bytes.TrimRight(parts[1], "\x00"))
				metadata[key] = val
				fmt.Printf("     [+] Found Metadata: %s = %q\n", key, val)
			}
		}

		if chunkType == "IEND" {
			iendOffset = realOffset + int64(12+length)
			fmt.Printf("  -> Reached [IEND] marker at offset 0x%08X\n", realOffset)
			break
		}
	}

	// Print summary of discovered metadata
	if len(metadata) > 0 {
		fmt.Println("\n[+] Recovered Metadata Elements:")
		for k, v := range metadata {
			fmt.Printf("    * %s: %s\n", k, v)
		}
	}

	// Check for trailing data after IEND
	if iendOffset != -1 && int64(len(fileData)) > iendOffset {
		trailing := fileData[iendOffset:]
		fmt.Println("\n==========================================================")
		fmt.Printf("[!] ALERT: Trailing payload detected after IEND!\n")
		fmt.Printf("[!] Trailing Data Size: %d bytes (%.2f KB)\n", len(trailing), float64(len(trailing))/1024)
		fmt.Printf("[!] Starting Offset:    0x%08X\n", iendOffset)

		entropy := calcEntropy(trailing)
		fmt.Printf("[*] Shannon Entropy:    %.4f / 8.0000\n", entropy)

		// Check for embedded magic signatures
		checkSignatures(trailing)

		// Print hex preview
		fmt.Println("\n[*] First 64 Bytes Hex Dump:")
		for i := 0; i < min(len(trailing), 64); i += 16 {
			fmt.Printf("  0x%04X: ", i)
			end := min(i+16, len(trailing))
			for j := i; j < end; j++ {
				fmt.Printf("%02X ", trailing[j])
			}
			for j := end; j < i+16; j++ {
				fmt.Print("   ")
			}
			fmt.Print(" | ")
			for j := i; j < end; j++ {
				if trailing[j] >= 32 && trailing[j] <= 126 {
					fmt.Printf("%c", trailing[j])
				} else {
					fmt.Print(".")
				}
			}
			fmt.Println()
		}

		// Save trailing data if requested
		if *dumpTrailing != "" {
			err := os.WriteFile(*dumpTrailing, trailing, 0644)
			if err != nil {
				fmt.Printf("[-] Failed to save trailing data: %v\n", err)
			} else {
				fmt.Printf("[+] Trailing payload dumped to: %s\n", *dumpTrailing)
			}
		}
		fmt.Println("==========================================================")
	} else {
		fmt.Println("\n[+] Clean File: No hidden bytes appended after IEND.")
	}

	// Extract readable strings from non-image chunks
	fmt.Println("\n[*] Non-IDAT Printable Strings:")
	for _, chunk := range chunks {
		if chunk.Type != "IDAT" && chunk.Type != "IHDR" && chunk.Type != "IEND" {
			extractPrintable(chunk.Type, chunk.Data)
		}
	}
}

func checkSignatures(data []byte) {
	sigs := map[string][]byte{
		"ZIP Archive":   {0x50, 0x4B, 0x03, 0x04},
		"GZIP Stream":   {0x1F, 0x8B},
		"7-Zip Archive": {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
		"RAR Archive":   {0x52, 0x61, 0x72, 0x21},
		"PCAP Capture":  {0xD4, 0xC3, 0xB2, 0xA1},
		"PCAPNG File":   {0x0A, 0x0D, 0x0D, 0x0A},
		"ELF Binary":    {0x7F, 0x45, 0x4C, 0x46},
	}

	for name, sig := range sigs {
		if bytes.HasPrefix(data, sig) {
			fmt.Printf("    -> [MATCH] Data begins with %s magic bytes!\n", name)
		} else if idx := bytes.Index(data, sig); idx != -1 {
			fmt.Printf("    -> [EMBEDDED] Found %s magic bytes at offset +0x%X\n", name, idx)
		}
	}
}

func calcEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[byte]int)
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	total := float64(len(data))
	for _, count := range counts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func extractPrintable(chunkType string, data []byte) {
	var current strings.Builder
	for _, b := range data {
		if unicode.IsPrint(rune(b)) {
			current.WriteByte(b)
		} else {
			if current.Len() >= 4 {
				fmt.Printf("    [%s] %s\n", chunkType, current.String())
			}
			current.Reset()
		}
	}
	if current.Len() >= 4 {
		fmt.Printf("    [%s] %s\n", chunkType, current.String())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
