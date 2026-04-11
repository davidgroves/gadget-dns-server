# DNS label compression example (RFC 1035)

The server uses RFC 1035 label compression by default: repeated domain names in a response are replaced with pointers, reducing wire size. Use **set-nocompress** to send the same response without compression (e.g. to test that resolvers accept both forms).

## Try it

With the server running for zone `example.com`:

```bash
# Compressed (default): response uses label compression
dig @127.0.0.1 -p 5353 counter.example.com TXT

# Uncompressed: same logical content, larger wire size
dig @127.0.0.1 -p 5353 set-nocompress.counter.example.com TXT
```

Stack **set-nocompress** with any gadget or set-answer to get uncompressed output, e.g. `set-nocompress.myip.example.com`, `set-nocompress.set-answer-1-2-3-4.example.com A`.

## Impressive compression

When the response contains many RRs that share the same long owner name, compression saves a lot. The unit test `TestHandler_Compression_Impressive` builds a response with five A records under a long name (multiple `set-answer-*` labels). Example output:

```
compression: 745 bytes (uncompressed) -> 215 bytes (compressed), saved 530 bytes (71%)
```

Run that test:

```bash
go test -v -run TestHandler_Compression_Impressive ./internal/handler/
```

To see a large compression ratio over the wire, query a name that produces many records with the same owner, then compare with `set-nocompress`:

```bash
# Many A records, long name => big compression gain
dig @127.0.0.1 -p 5353 set-answer-1-0-0-1.set-answer-2-0-0-2.set-answer-3-0-0-3.set-answer-4-0-0-4.set-answer-5-0-0-5.example.com A
# Same query with set-nocompress prefix would return the same data but in uncompressed form (larger UDP payload)
```
