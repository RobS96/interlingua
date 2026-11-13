# CCSDS space data systems standards

The Consultative Committee for Space Data Systems publishes the protocols
most civil space missions use. interlingua works with them at the packet
layer and above.

| Standard | Relation |
|---|---|
| CCSDS 133.0-B-2, *Space Packet Protocol* | **Implemented** (`ccsds` module): primary header encode/decode, APIDs 0–2046 (2047 idle), 14-bit sequence counts, segmentation (first / continuation / last / unsegmented) and reassembly with gap and size checks. Conformance: `spec/vectors/ccsds.rsp` |
| CCSDS 355.0-B, *Space Data Link Security (SDLS)* | **Complementary**: SDLS protects transfer frames on one space link; interlingua protects messages end to end across links, ground networks and relays. Use both on command links |
| CCSDS 352.0-B, *Cryptographic Algorithms* | **Consistent**: it recommends AES with GCM for authenticated encryption; interlingua seals with AES-256-GCM |
| CCSDS 351.0-M, *Security Architecture for Space Data Systems* | **Informative**: interlingua sits in its application layer, with authentication, integrity and confidentiality end to end |
| CCSDS 734.20-O, *Bundle Protocol* (adopting RFC 9171) | **Planned**: envelopes as bundle payloads for delay-tolerant paths ([ROADMAP.md](../ROADMAP.md)) |
| CCSDS 301.0-B, *Time Code Formats* | **Edge conversion**: missions using CUC or CDS time convert to Unix milliseconds at the router host |

## Carrying envelopes in Space Packets

```bash
il ccsds frame --apid 291 --tc --max-data 1024 < envelope.il > packets.bin
il ccsds deframe < packets.bin > envelope.il
```

A 6.5 KB sealed telecommand fits in seven packets of 1024 data octets. The
packet layer adds no security; a lost or reordered segment discards the whole
message rather than delivering a partial one, and the envelope's signature
decides authenticity. A secondary header, if a mission defines one, travels
inside the data field and is outside the envelope.
