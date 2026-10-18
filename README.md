# png-forensics

PNG chunk and metadata parser.

## Usage

```bash
go run main.go -file absolute.png
```

Dump trailing payload if present:
```bash
go run main.go -file absolute.png -dump-trailing payload.bin
```

## Output

```console
$ go run main.go -file absolute.png
==========================================================
[*] PNG Forensics & Metadata Analyzer
[*] Target File: absolute.png
==========================================================
[+] Total File Size: 2002404 bytes (1.91 MB)
[+] PNG Signature Verified: 89 50 4E 47 0D 0A 1A 0A

[*] Parsing PNG Chunks:
  -> Chunk [IHDR] at offset 0x00000008 (Length: 13 bytes, CRC: 0xEE8C3168)
  -> Chunk [tEXt] at offset 0x00000021 (Length: 18 bytes, CRC: 0x051A4154)
     [+] Found Metadata: Artist = "@Skye_Chi14"
  -> Chunk [tEXt] at offset 0x0000003F (Length: 13 bytes, CRC: 0xDA125C3B)
     [+] Found Metadata: Comment = "NOISE"
  -> Chunk [IEND] at offset 0x001ACBB3 (Length: 0 bytes, CRC: 0xAE426082)
  -> Reached [IEND] marker at offset 0x001ACBB3

[+] Recovered Metadata Elements:
    * Artist: @Skye_Chi14
    * Comment: NOISE

==========================================================
[!] ALERT: Trailing payload detected after IEND!
[!] Trailing Data Size: 246309 bytes (240.54 KB)
[!] Starting Offset:    0x001ACBBF
[*] Shannon Entropy:    7.9245 / 8.0000
    -> [EMBEDDED] Found GZIP Stream magic bytes at offset +0x28C00

[*] First 64 Bytes Hex Dump:
  0x0000: 96 24 AE F8 8B 2B 5F 71 11 5B 73 80 6B 97 20 78  | .$...+_q.[s.k. x
  0x0010: C1 C3 89 DF 38 88 23 DF C8 E5 2F 4C 1F 4D 7C AC  | ....8.#.../L.M|.
  0x0020: F3 71 C5 07 03 1F A6 C8 99 4F 73 45 8F 3F 92 F6  | .q.......OsE.?..
  0x0030: 4C E2 62 9E F9 C6 8E 17 07 3E B1 9D BF C5 4F BB  | L.b......>....O.
==========================================================
```
