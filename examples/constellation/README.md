# Example: a small constellation

```bash
cargo build -p interlingua-cli
examples/constellation/run.sh target/debug/il
```

Four domains ([policy.ndb](policy.ndb)): `ground-station`, `relay-sat`,
`spacecraft`, `science-lab` (roles, not organisations). The script:

1. generates ML-DSA-87 + ML-KEM-1024 keys for each (secret bundles mode 0600);
2. seals a telecommand from the ground station to the spacecraft;
3. routes it hop by hop: `forward:relay-sat`, `forward:spacecraft`, `deliver`;
4. opens it at the spacecraft, and shows the relay cannot (`WrongRecipient`);
5. refuses a `conf=moderate` message to the `conf=low` science lab
   (`ConfidentialityExceedsDestination`);
6. catches one altered byte (`BadSignature`);
7. verifies every router's SHA-384 audit chain;
8. frames the envelope as CCSDS telecommand Space Packets and reassembles it
   byte for byte.

Everything happens in a temporary directory that is deleted at the end.
