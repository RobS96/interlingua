package interlingua

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// record is one .rsp record (NIST CAVP layout: "name = value" lines).
type record struct {
	section string
	fields  map[string]string
}

func vectorsDir() string {
	if d := os.Getenv("INTERLINGUA_VECTORS"); d != "" {
		return d
	}
	return filepath.Join("..", "..", "spec", "vectors")
}

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorsDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseRSP(t *testing.T, name string) []record {
	t.Helper()
	var out []record
	section := ""
	cur := record{fields: map[string]string{}}
	flush := func() {
		if len(cur.fields) > 0 {
			out = append(out, cur)
		}
		cur = record{section: section, fields: map[string]string{}}
	}
	for _, raw := range strings.Split(string(readVector(t, name)), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "#"):
		case line == "":
			flush()
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			flush()
			section = strings.TrimSpace(line[1 : len(line)-1])
			cur.section = section
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("%s: malformed line %q", name, line)
			}
			cur.section = section
			cur.fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	flush()
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func errID(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.ID
	}
	return fmt.Sprint(err)
}

func TestABIAndVersion(t *testing.T) {
	if !strings.HasPrefix(Version(), "interlingua ") {
		t.Fatalf("unexpected version %q", Version())
	}
}

func TestCBORVectors(t *testing.T) {
	for _, r := range parseRSP(t, "cbor.rsp") {
		in := mustHex(t, r.fields["cbor"])
		out, err := CBORCanonical(in)
		switch r.fields["expect"] {
		case "accept":
			if err != nil || !bytes.Equal(out, in) {
				t.Errorf("cbor %s: want canonical round trip, got %v", r.fields["cbor"], err)
			}
			if want, ok := r.fields["diag"]; ok {
				if got, _ := CBORDiag(in); got != want {
					t.Errorf("cbor %s: diag %q, want %q", r.fields["cbor"], got, want)
				}
			}
		case "reject":
			if err == nil || errID(err) != r.fields["error"] {
				t.Errorf("cbor %s: want %s, got %v", r.fields["cbor"], r.fields["error"], err)
			}
		}
	}
}

func TestLabelVectors(t *testing.T) {
	for _, r := range parseRSP(t, "label.rsp") {
		text, cbor, err := NormalizeLabel(r.fields["text"])
		if r.fields["expect"] == "accept" {
			if err != nil || text != r.fields["canonical"] || !bytes.Equal(cbor, mustHex(t, r.fields["cbor"])) {
				t.Errorf("label %q: got %q %x %v", r.fields["text"], text, cbor, err)
			}
		} else if errID(err) != r.fields["error"] {
			t.Errorf("label %q: want %s, got %v", r.fields["text"], r.fields["error"], err)
		}
	}
}

func TestCCSDSVectors(t *testing.T) {
	flags := map[string]uint8{"continuation": 0, "first": 1, "last": 2, "unsegmented": 3}
	for _, r := range parseRSP(t, "ccsds.rsp") {
		wire := mustHex(t, r.fields["packet"])
		got, used, err := DecodeSpacePacket(wire)
		if r.fields["expect"] != "accept" {
			if errID(err) != r.fields["error"] {
				t.Errorf("ccsds %s: want %s, got %v", r.fields["packet"], r.fields["error"], err)
			}
			continue
		}
		apid, _ := strconv.Atoi(r.fields["apid"])
		count, _ := strconv.Atoi(r.fields["count"])
		want := SpacePacket{r.fields["type"] == "tc", r.fields["sec"] == "1", uint16(apid), flags[r.fields["flags"]], uint16(count), mustHex(t, r.fields["data"])}
		if err != nil || used != len(wire) || got.APID != want.APID || got.SequenceCount != want.SequenceCount ||
			got.SequenceFlags != want.SequenceFlags || got.Telecommand != want.Telecommand ||
			got.SecondaryHeader != want.SecondaryHeader || !bytes.Equal(got.Data, want.Data) {
			t.Errorf("ccsds decode %s: got %+v %v", r.fields["packet"], got, err)
		}
		if enc, err := want.Encode(); err != nil || !bytes.Equal(enc, wire) {
			t.Errorf("ccsds encode %s: got %x %v", r.fields["packet"], enc, err)
		}
	}
}

// secretFor returns the test secret bundle for domain.
func secretFor(t *testing.T, domain string) []byte {
	t.Helper()
	const magic = "interlingua-secret-key v1\n"
	text := string(readVector(t, "test-secrets.txt"))
	for _, chunk := range strings.Split(text, magic)[1:] {
		if strings.HasPrefix(chunk, "domain "+domain+"\n") {
			return []byte(magic + chunk)
		}
	}
	t.Fatalf("no test key for %s", domain)
	return nil
}

func TestEnvelopeVectors(t *testing.T) {
	ring := readVector(t, "keyring.pub")
	for _, r := range parseRSP(t, "envelope.rsp") {
		var secret []byte
		if d, ok := r.fields["recipient"]; ok {
			secret = secretFor(t, d)
		}
		payload, err := Open(secret, ring, mustHex(t, r.fields["envelope"]))
		if r.fields["expect"] == "valid" {
			if err != nil || !bytes.Equal(payload, mustHex(t, r.fields["payload"])) {
				t.Errorf("envelope %s: %v", r.fields["name"], err)
			}
		} else if want := strings.TrimPrefix(r.fields["expect"], "error:"); errID(err) != want {
			t.Errorf("envelope %s: want %s, got %v", r.fields["name"], want, err)
		}
	}
}

func TestRoutingVectors(t *testing.T) {
	ring := readVector(t, "keyring.pub")
	policy := string(readVector(t, "routing-policy.ndb"))
	routers := map[string]*Router{}
	section := "\x00"
	var forwarded []byte
	defer func() {
		for _, r := range routers {
			r.Close()
		}
	}()
	for _, r := range parseRSP(t, "routing.rsp") {
		if r.section != section {
			for _, rt := range routers {
				rt.Close()
			}
			routers, forwarded, section = map[string]*Router{}, nil, r.section
		}
		node := r.fields["node"]
		rt, ok := routers[node]
		if !ok {
			var err error
			if rt, err = NewRouter(policy, ring, node); err != nil {
				t.Fatal(err)
			}
			routers[node] = rt
		}
		env := forwarded
		if r.fields["envelope"] != "forwarded" {
			env = mustHex(t, r.fields["envelope"])
		}
		from := r.fields["from"]
		if from == "-" {
			from = ""
		}
		ms, _ := strconv.ParseInt(r.fields["now"], 10, 64)
		d, err := rt.Route(env, from, time.UnixMilli(ms))
		got := d.Verdict
		switch d.Verdict {
		case "forward":
			got += ":" + d.NextHop
		case "reject":
			got += ":" + d.Reason
		}
		if err != nil || got != r.fields["expect"] {
			t.Errorf("routing [%s] %s: want %s, got %s (%v)", r.section, r.fields["name"], r.fields["expect"], got, err)
		}
		forwarded = d.Forward
	}
}
