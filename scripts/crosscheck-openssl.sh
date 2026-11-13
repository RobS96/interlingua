#!/bin/sh
# crosscheck-openssl.sh: check the conformance vectors with OpenSSL, an
# implementation that shares no code with interlingua.
#
#   scripts/crosscheck-openssl.sh <path-to-il> <vectors-dir>
#
# Checks (OpenSSL 3.5 or later):
#   1. every valid envelope's ML-DSA-87 signature verifies (pure mode, empty context)
#   2. the sealed vector's ML-KEM-1024 ciphertext decapsulates to the recorded secret
#   3. HKDF-SHA-384 over that secret gives the recorded AES-256 key and nonce
# AES-256-GCM is not available from the openssl command line; the Go, Swift
# and Java runners check it.
#
# Exit 0 = all checks passed, or SKIP (no OpenSSL 3.5+); 1 = a check failed.
set -eu

IL=${1:?usage: crosscheck-openssl.sh <il> <vectors-dir>}
DIR=${2:?usage: crosscheck-openssl.sh <il> <vectors-dir>}
OPENSSL=${OPENSSL:-openssl}

if ! "$OPENSSL" list -signature-algorithms 2>/dev/null | grep -qi 'ML-DSA-87'; then
    echo "SKIP: $("$OPENSSL" version 2>/dev/null || echo 'no openssl') has no ML-DSA-87 (OpenSSL 3.5+ needed)"
    exit 0
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/il-openssl.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
pass=0
fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL $*" >&2; }
unhex() { printf '%s' "$1" | xxd -r -p > "$2"; }

# One record per line: name|expect|signer|signed|signature|recipient|kem-ct|kem-ss|aead-key|aead-nonce|aead-aad
awk -F' = ' '
    /^#/ || /^\[/ { next }
    NF == 0 { if (n != "") print n "|" e "|" s "|" sd "|" sg "|" r "|" kc "|" ks "|" ak "|" an "|" aa; n=e=s=sd=sg=r=kc=ks=ak=an=aa=""; next }
    $1 == "name" { n = $2 } $1 == "expect" { e = $2 } $1 == "signer" { s = $2 } $1 == "signed" { sd = $2 }
    $1 == "signature" { sg = $2 } $1 == "recipient" { r = $2 } $1 == "kem-ct" { kc = $2 } $1 == "kem-ss" { ks = $2 }
    $1 == "aead-key" { ak = $2 } $1 == "aead-nonce" { an = $2 } $1 == "aead-aad" { aa = $2 }
    END { if (n != "") print n "|" e "|" s "|" sd "|" sg "|" r "|" kc "|" ks "|" ak "|" an "|" aa }
' "$DIR/envelope.rsp" > "$WORK/records"

# The public bundle of one domain, as a file `il spki` can read.
bundle() {
    awk -v d="$1" '
        /^interlingua-public-key v1/ { keep = 0; buf = $0 "\n"; next }
        $1 == "domain" { keep = ($2 == d) }
        { buf = buf $0 "\n" }
        keep && $1 == "mlkem1024-ek" { printf "%s", buf; exit }
    ' "$DIR/keyring.pub" > "$WORK/$1.pub"
}

while IFS='|' read -r name expect signer signed sig recipient kemct kemss aeadkey aeadnonce aeadaad; do
    [ "$expect" = valid ] || continue
    bundle "$signer"
    "$IL" spki "$WORK/$signer.pub" > "$WORK/spki.der"
    unhex "$signed" "$WORK/signed.bin"
    unhex "$sig" "$WORK/sig.bin"
    if "$OPENSSL" pkeyutl -verify -pubin -inkey "$WORK/spki.der" -keyform DER -rawin \
        -in "$WORK/signed.bin" -sigfile "$WORK/sig.bin" > /dev/null 2>&1; then
        ok
    else
        bad "OpenSSL rejects the ML-DSA-87 signature of '$name'"
    fi

    [ -n "$kemss" ] || continue
    # PKCS#8 of the expanded ML-KEM-1024 key: OID 2.16.840.1.101.3.4.4.3 and the
    # 3168-byte key as the `expandedKey` choice (IETF LAMPS ML-KEM X.509 profile).
    dk=$(awk -v d="$recipient" '
        /^interlingua-secret-key v1/ { keep = 0 }
        $1 == "domain" { keep = ($2 == d) }
        keep && $1 == "mlkem1024-dk" { print $2; exit }
    ' "$DIR/test-secrets.txt")
    unhex "30820c78020100300b060960864801650304040304820c6404820c60$dk" "$WORK/dk.der"
    unhex "$kemct" "$WORK/ct.bin"
    if "$OPENSSL" pkeyutl -decap -inkey "$WORK/dk.der" -keyform DER -in "$WORK/ct.bin" \
        -secret "$WORK/ss.bin" > /dev/null 2>&1 &&
        [ "$(xxd -p "$WORK/ss.bin" | tr -d '\n')" = "$kemss" ]; then
        ok
    else
        bad "OpenSSL ML-KEM-1024 decapsulation of '$name' differs from the recorded secret"
    fi

    # Salt = SHA-384(protected header); the header is inside the AAD
    # CBOR ["IL1-Encrypt", protected] after 13 bytes and a 2- or 3-byte length.
    form=$(printf '%s' "$aeadaad" | cut -c27-28)
    if [ "$form" = 58 ]; then
        len=$((0x$(printf '%s' "$aeadaad" | cut -c29-30)))
        start=31
    else
        len=$((0x$(printf '%s' "$aeadaad" | cut -c29-32)))
        start=33
    fi
    printf '%s' "$aeadaad" | cut -c"$start"-$((start + 2 * len - 1)) | xxd -r -p > "$WORK/protected.bin"
    salt=$("$OPENSSL" dgst -sha384 -binary "$WORK/protected.bin" | xxd -p | tr -d '\n')
    bundle "$recipient"
    ek=$(awk '$1 == "mlkem1024-ek" { print $2 }' "$WORK/$recipient.pub")
    printf '%s' "$ek" | xxd -r -p > "$WORK/ek.bin"
    kid=$("$OPENSSL" dgst -sha384 -binary "$WORK/ek.bin" | xxd -p | tr -d '\n')
    info="$(printf 'IL1-Seal-AES256GCM' | xxd -p | tr -d '\n')$kid"
    okm=$("$OPENSSL" kdf -keylen 44 -kdfopt digest:SHA384 -kdfopt "hexkey:$kemss" \
        -kdfopt "hexsalt:$salt" -kdfopt "hexinfo:$info" HKDF | tr -d ':\n' | tr 'A-F' 'a-f')
    if [ "$okm" = "$aeadkey$aeadnonce" ]; then ok; else bad "OpenSSL HKDF-SHA-384 differs for '$name'"; fi
done < "$WORK/records"

echo "OpenSSL cross-check ($("$OPENSSL" version | cut -d' ' -f1-2)): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
