#!/bin/sh
# A sealed telecommand crosses a relay to a spacecraft, a policy violation is
# refused, every router's audit chain verifies, and the envelope is framed as
# CCSDS Space Packets. Uses only the `il` CLI.
#
#   examples/constellation/run.sh [path-to-il]
set -eu

IL=${1:-target/debug/il}
IL=$(cd "$(dirname "$IL")" && pwd)/$(basename "$IL")
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/il-demo.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
cd "$WORK"
NOW=$(($(date +%s) * 1000))
say() { printf '\n== %s\n' "$*"; }

say "1. Keys: one ML-DSA-87 + ML-KEM-1024 pair per domain"
for d in ground-station relay-sat spacecraft science-lab; do
    "$IL" keygen "$d" "$d" 2>/dev/null
    cat "$d.pub" >> keyring.pub
    printf '%-15s secret %s (mode %s)\n' "$d" "$d.key" "$(stat -f %Lp "$d.key" 2>/dev/null || stat -c %a "$d.key")"
done

say "2. ground-station seals a telecommand to spacecraft (conf=moderate, so sealing is mandatory)"
printf 'SET MODE SCIENCE; SLEW +12.5 DEG' |
    "$IL" seal --key ground-station.key --dst spacecraft --to spacecraft.pub \
        --label 'conf=moderate integ=high avail=high comp=tt-c' --type text/plain --ttl 600 --now "$NOW" > cmd.il
printf '%s bytes on the wire\n' "$(wc -c < cmd.il | tr -d ' ')"
"$IL" inspect < cmd.il

say "3. Hop by hop: each router verifies, applies the policy, audits"
"$IL" route --policy "$HERE/policy.ndb" --keyring keyring.pub --node ground-station \
    --audit ground.audit --out hop1.il --now "$NOW" < cmd.il
"$IL" route --policy "$HERE/policy.ndb" --keyring keyring.pub --node relay-sat --from ground-station \
    --audit relay.audit --out hop2.il --now "$NOW" < hop1.il
"$IL" route --policy "$HERE/policy.ndb" --keyring keyring.pub --node spacecraft --from relay-sat \
    --audit craft.audit --now "$NOW" < hop2.il

say "4. Only spacecraft can open it"
"$IL" open --keyring keyring.pub --key spacecraft.key < hop2.il; echo
if "$IL" open --keyring keyring.pub --key relay-sat.key < hop2.il 2>err.txt; then exit 1; fi
printf 'relay-sat: %s\n' "$(cat err.txt)"

say "5. Policy at work: science-lab is cleared for conf=low only"
printf 'calibration table v7' |
    "$IL" seal --key ground-station.key --dst science-lab --to science-lab.pub \
        --label 'conf=moderate integ=moderate avail=low comp=science' --now "$NOW" > leak.il
if "$IL" route --policy "$HERE/policy.ndb" --keyring keyring.pub --node ground-station \
    --audit ground.audit --now "$NOW" < leak.il 2>/dev/null; then exit 1; fi

say "6. Tampering is caught by every router"
cp cmd.il tampered.il
printf 'X' | dd of=tampered.il bs=1 seek=300 conv=notrunc 2>/dev/null
if "$IL" route --policy "$HERE/policy.ndb" --keyring keyring.pub --node ground-station \
    --audit ground.audit --now "$NOW" < tampered.il 2>/dev/null; then exit 1; fi

say "7. Audit chains (SHA-384 hash chains) verify"
for a in ground relay craft; do printf '%-7s ' "$a"; "$IL" audit-verify "$a.audit"; done
tail -n 1 ground.audit | tr ' ' '\n' | grep -E '^(verdict|reason|code|auth)='

say "8. CCSDS 133.0-B-2: the envelope as telecommand Space Packets (APID 0x123, 1024-octet data fields)"
"$IL" ccsds frame --apid 291 --tc --max-data 1024 < hop2.il > packets.bin
printf '%s envelope bytes -> %s packet bytes\n' "$(wc -c < hop2.il | tr -d ' ')" "$(wc -c < packets.bin | tr -d ' ')"
"$IL" ccsds deframe < packets.bin | cmp - hop2.il && echo "reassembled byte-for-byte"
