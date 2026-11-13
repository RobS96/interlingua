package interlingua

// Independent-implementation checks: Go's standard library (crypto/mldsa,
// crypto/mlkem, crypto/hkdf, crypto/aes) against the Rust reference, with no
// interlingua code on the Go side of the comparison.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

type domainKeys struct{ name, pk, ek []byte }

// keyring parses keyring.pub in file order.
func keyring(t *testing.T) []domainKeys {
	t.Helper()
	var out []domainKeys
	for _, line := range strings.Split(string(readVector(t, "keyring.pub")), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "domain":
			out = append(out, domainKeys{name: []byte(v)})
		case "mldsa87-pk":
			out[len(out)-1].pk = mustHex(t, v)
		case "mlkem1024-ek":
			out[len(out)-1].ek = mustHex(t, v)
		}
	}
	return out
}

func keysFor(t *testing.T, domain string) domainKeys {
	for _, k := range keyring(t) {
		if string(k.name) == domain {
			return k
		}
	}
	t.Fatalf("no keys for %s", domain)
	return domainKeys{}
}

// The published ML-DSA-87 test keys come from seeds 0x01…01 to 0x06…06 in
// keyring order: Go's FIPS 204 key generation must derive the same keys.
func TestGoMLDSAKeyGenMatchesKeyring(t *testing.T) {
	for i, k := range keyring(t) {
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), bytes.Repeat([]byte{byte(i + 1)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sk.PublicKey().Bytes(), k.pk) {
			t.Errorf("%s: Go derives a different ML-DSA-87 public key from seed %d", k.name, i+1)
		}
		if _, err := mlkem.NewEncapsulationKey1024(k.ek); err != nil {
			t.Errorf("%s: Go rejects the ML-KEM-1024 encapsulation key: %v", k.name, err)
		}
	}
}

func TestGoVerifiesRustSignatures(t *testing.T) {
	checked := 0
	for _, r := range parseRSP(t, "envelope.rsp") {
		if r.fields["expect"] != "valid" {
			continue
		}
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), keysFor(t, r.fields["signer"]).pk)
		if err != nil {
			t.Fatal(err)
		}
		signed, sig := mustHex(t, r.fields["signed"]), mustHex(t, r.fields["signature"])
		if err := mldsa.Verify(pk, signed, sig, nil); err != nil {
			t.Errorf("%s: crypto/mldsa rejects the Rust signature: %v", r.fields["name"], err)
		}
		signed[len(signed)-1] ^= 1
		if mldsa.Verify(pk, signed, sig, nil) == nil {
			t.Errorf("%s: a modified message verified", r.fields["name"])
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no valid envelope vectors")
	}
}

// protectedFromAAD extracts the protected header from CBOR ["IL1-Encrypt", protected].
func protectedFromAAD(t *testing.T, aad []byte) []byte {
	prefix := append([]byte{0x82, 0x6b}, "IL1-Encrypt"...)
	if !bytes.HasPrefix(aad, prefix) {
		t.Fatalf("unexpected AAD shape %x", aad[:16])
	}
	rest := aad[len(prefix):]
	switch rest[0] {
	case 0x58:
		return rest[2 : 2+int(rest[1])]
	case 0x59:
		return rest[3 : 3+int(binary.BigEndian.Uint16(rest[1:3]))]
	}
	t.Fatalf("unexpected protected-header length form %x", rest[0])
	return nil
}

func TestGoOpensRustSealedVector(t *testing.T) {
	for _, r := range parseRSP(t, "envelope.rsp") {
		if r.fields["expect"] != "valid" || r.fields["kem-ss"] == "" {
			continue
		}
		ek := keysFor(t, r.fields["recipient"]).ek
		kid := sha512.Sum384(ek)
		aad := mustHex(t, r.fields["aead-aad"])
		salt := sha512.Sum384(protectedFromAAD(t, aad))
		okm, err := hkdf.Key(sha512.New384, mustHex(t, r.fields["kem-ss"]), salt[:], "IL1-Seal-AES256GCM"+string(kid[:]), 44)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(okm) != r.fields["aead-key"]+r.fields["aead-nonce"] {
			t.Fatalf("%s: HKDF-SHA-384 output differs from the Rust derivation", r.fields["name"])
		}
		block, _ := aes.NewCipher(okm[:32])
		gcm, _ := cipher.NewGCM(block)
		plain, err := gcm.Open(nil, okm[32:], mustHex(t, r.fields["aead-ct"]), aad)
		if err != nil || !bytes.Equal(plain, mustHex(t, r.fields["payload"])) {
			t.Fatalf("%s: AES-256-GCM open with Go: %v", r.fields["name"], err)
		}
	}
}

// cb is a minimal deterministic CBOR writer: just what an envelope needs.
type cb struct{ b []byte }

func (c *cb) head(major byte, n uint64) {
	switch {
	case n < 24:
		c.b = append(c.b, major<<5|byte(n))
	case n <= 0xff:
		c.b = append(c.b, major<<5|24, byte(n))
	case n <= 0xffff:
		c.b = binary.BigEndian.AppendUint16(append(c.b, major<<5|25), uint16(n))
	case n <= 0xffffffff:
		c.b = binary.BigEndian.AppendUint32(append(c.b, major<<5|26), uint32(n))
	default:
		c.b = binary.BigEndian.AppendUint64(append(c.b, major<<5|27), n)
	}
}
func (c *cb) uint(n uint64)  { c.head(0, n) }
func (c *cb) bytes(b []byte) { c.head(2, uint64(len(b))); c.b = append(c.b, b...) }
func (c *cb) text(s string)  { c.head(3, uint64(len(s))); c.b = append(c.b, s...) }

// An envelope built with nothing but Go's standard library, following
// docs/SPECIFICATION.md, must open and route in the Rust reference.
func TestGoBuiltEnvelopeOpensAndRoutesInRust(t *testing.T) {
	const t0 = 1_767_225_600_000
	created, expires := uint64(t0+5_000), uint64(t0+5_000+3_600_000)
	signer, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), bytes.Repeat([]byte{1}, 32)) // ground-ops
	if err != nil {
		t.Fatal(err)
	}
	signerKID := sha512.Sum384(signer.PublicKey().Bytes())
	ekBytes := keysFor(t, "space-segment").ek
	recipientKID := sha512.Sum384(ekBytes)

	id := make([]byte, 16)
	rand.Read(id)
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], created)
	copy(id, ms[2:])
	id[6], id[8] = 0x70|id[6]&0x0f, 0x80|id[8]&0x3f

	var h cb
	h.head(5, 12)
	h.uint(1)
	h.uint(1) // version
	h.uint(2)
	h.uint(1) // suite IL1-CNSA2
	h.uint(3)
	h.bytes(id)
	h.uint(4)
	h.text("ground-ops")
	h.uint(5)
	h.text("space-segment")
	h.uint(6)
	h.head(4, 4)
	h.uint(2)
	h.uint(3)
	h.uint(3)
	h.head(4, 1)
	h.text("tt-c")
	h.uint(7)
	h.uint(created)
	h.uint(8)
	h.uint(expires)
	h.uint(9)
	h.uint(8)
	h.uint(10)
	h.text("text/plain")
	h.uint(11)
	h.b = append(h.b, 0xf5) // sealed: true
	h.uint(12)
	h.bytes(signerKID[:])
	protected := h.b

	ek, err := mlkem.NewEncapsulationKey1024(ekBytes)
	if err != nil {
		t.Fatal(err)
	}
	ss, kemCT := ek.Encapsulate()
	salt := sha512.Sum384(protected)
	okm, err := hkdf.Key(sha512.New384, ss, salt[:], "IL1-Seal-AES256GCM"+string(recipientKID[:]), 44)
	if err != nil {
		t.Fatal(err)
	}
	var aad cb
	aad.head(4, 2)
	aad.text("IL1-Encrypt")
	aad.bytes(protected)
	block, _ := aes.NewCipher(okm[:32])
	gcm, _ := cipher.NewGCM(block)
	message := []byte("built by Go's standard library")
	var sealed cb
	sealed.head(4, 3)
	sealed.bytes(recipientKID[:])
	sealed.bytes(kemCT)
	sealed.bytes(gcm.Seal(nil, okm[32:], message, aad.b))

	var toSign cb
	toSign.head(4, 3)
	toSign.text("IL1-Sign")
	toSign.bytes(protected)
	toSign.bytes(sealed.b)
	sig, err := signer.Sign(rand.Reader, toSign.b, &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var env cb
	env.head(4, 4)
	env.bytes(protected)
	env.head(5, 1)
	env.uint(1)
	env.uint(8)
	env.bytes(sealed.b)
	env.bytes(sig)

	ring := readVector(t, "keyring.pub")
	got, err := Open(secretFor(t, "space-segment"), ring, env.b)
	if err != nil || !bytes.Equal(got, message) {
		t.Fatalf("Rust could not open the Go-built envelope: %v", err)
	}
	router, err := NewRouter(string(readVector(t, "routing-policy.ndb")), ring, "ground-ops")
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	d, err := router.Route(env.b, "", time.UnixMilli(t0+6_000))
	if err != nil || d.Verdict != "forward" || d.NextHop != "relay-alpha" {
		t.Fatalf("routing the Go-built envelope: %+v %v", d, err)
	}
}
