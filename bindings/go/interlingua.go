// Package interlingua is the Go binding of the interlingua C ABI: canonical
// envelopes signed with ML-DSA-87 and sealed with ML-KEM-1024 + AES-256-GCM,
// label-based routing between trust domains, and CCSDS space packets.
//
// The native library is linked statically. Build it first, then point cgo at
// it, for example:
//
//	cargo build --release -p interlingua-ffi
//	CGO_LDFLAGS="$PWD/target/release/libinterlingua_ffi.a -lm" go test ./...
//
// Every call that can fail pins its goroutine to one OS thread for the call
// and the error lookup, because the C ABI reports errors per thread
// (docs/INTEROP.md, "Errors across threads").
package interlingua

/*
#cgo CFLAGS: -I${SRCDIR}/../c/include
#include <stdlib.h>
#include "interlingua.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// Error is a failure reported by the library.
type Error struct {
	Code    int32  // negative IL_E_* code
	ID      string // stable identifier, e.g. "BadSignature", "Cbor/NonPreferredFloat"
	Message string // human-readable detail
}

func (e *Error) Error() string { return fmt.Sprintf("interlingua: %s [%s]", e.Message, e.ID) }

// takeBuf copies a library buffer into Go memory and frees it.
func takeBuf(b *C.il_buf) []byte {
	defer C.il_buf_free(b)
	if b.ptr == nil || b.len == 0 {
		return nil
	}
	out := make([]byte, int(b.len))
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(b.ptr)), int(b.len)))
	return out
}

// call runs fn on one OS thread and turns a failure into an *Error.
func call(fn func() C.int32_t) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rc := fn()
	if rc == C.IL_OK {
		return nil
	}
	var id, msg C.il_buf
	C.il_last_error_id(&id)
	C.il_last_error_message(&msg)
	return &Error{Code: int32(rc), ID: string(takeBuf(&id)), Message: string(takeBuf(&msg))}
}

// ptr returns a C pointer to b's bytes (nil for an empty slice). The C side
// only borrows it for the duration of the call.
func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func cstr(s string) (*C.char, func()) {
	c := C.CString(s)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

// Version is the native library's version text.
func Version() string { return C.GoString(C.il_version()) }

// KeyGen creates ML-DSA-87 + ML-KEM-1024 keys for domain and returns the
// secret and public bundles. Protect the secret bundle like any private key.
func KeyGen(domain string) (secret, public []byte, err error) {
	d, free := cstr(domain)
	defer free()
	var s, p C.il_buf
	err = call(func() C.int32_t { return C.il_keygen(d, &s, &p) })
	secret, public = takeBuf(&s), takeBuf(&p)
	return secret, public, err
}

// SealOptions describe an envelope to build.
type SealOptions struct {
	Recipient   []byte // public bundle of Dst to seal the payload; nil sends plaintext
	Dst         string
	Label       string // e.g. "conf=moderate integ=high avail=low comp=tt-c"
	ContentType string // e.g. "application/octet-stream"
	Now         time.Time
	TTL         time.Duration
	MaxHops     uint8
}

// Seal builds, optionally seals, and signs an envelope from the sender's
// secret bundle (the sender's domain is the source).
func Seal(secret []byte, o SealOptions, payload []byte) ([]byte, error) {
	dst, f1 := cstr(o.Dst)
	defer f1()
	label, f2 := cstr(o.Label)
	defer f2()
	ct, f3 := cstr(o.ContentType)
	defer f3()
	var out C.il_buf
	err := call(func() C.int32_t {
		return C.il_seal(ptr(secret), C.size_t(len(secret)), ptr(o.Recipient), C.size_t(len(o.Recipient)),
			dst, label, ct, C.uint64_t(o.Now.UnixMilli()), C.uint64_t(o.TTL.Milliseconds()), C.uint8_t(o.MaxHops),
			ptr(payload), C.size_t(len(payload)), &out)
	})
	return takeBuf(&out), err
}

// Verify checks that envelope is signed by a keyring key bound to its source.
func Verify(keyring, envelope []byte) error {
	return call(func() C.int32_t {
		return C.il_verify(ptr(keyring), C.size_t(len(keyring)), ptr(envelope), C.size_t(len(envelope)))
	})
}

// Open verifies envelope and returns its plaintext. secret is the
// recipient's secret bundle, or nil for plaintext envelopes.
func Open(secret, keyring, envelope []byte) ([]byte, error) {
	var out C.il_buf
	err := call(func() C.int32_t {
		return C.il_open(ptr(secret), C.size_t(len(secret)), ptr(keyring), C.size_t(len(keyring)),
			ptr(envelope), C.size_t(len(envelope)), &out)
	})
	return takeBuf(&out), err
}

// Inspect describes an envelope header as attr=value text. Unverified.
func Inspect(envelope []byte) (string, error) {
	var out C.il_buf
	err := call(func() C.int32_t { return C.il_inspect(ptr(envelope), C.size_t(len(envelope)), &out) })
	return string(takeBuf(&out)), err
}

// Decision is a router's answer for one envelope.
type Decision struct {
	Verdict   string // deliver, forward or reject
	NextHop   string // set when forwarding
	Reason    string // ok, or the rejection reason
	AuditLine string // the hash-chained audit record
	Forward   []byte // the envelope to send on when forwarding
}

// Router decides for one trust domain. Safe for concurrent use.
type Router struct{ h *C.il_router }

// NewRouter creates a router for node from policy text and a keyring.
func NewRouter(policy string, keyring []byte, node string) (*Router, error) {
	p, f1 := cstr(policy)
	defer f1()
	n, f2 := cstr(node)
	defer f2()
	var h *C.il_router
	if err := call(func() C.int32_t { return C.il_router_new(p, ptr(keyring), C.size_t(len(keyring)), n, &h) }); err != nil {
		return nil, err
	}
	r := &Router{h: h}
	runtime.SetFinalizer(r, (*Router).Close)
	return r, nil
}

// Route decides what to do with envelope. from is the neighbouring domain
// it arrived from, or "" when a local sender handed it over.
func (r *Router) Route(envelope []byte, from string, now time.Time) (Decision, error) {
	var fromC *C.char
	if from != "" {
		c, free := cstr(from)
		defer free()
		fromC = c
	}
	var line, fwd C.il_buf
	err := call(func() C.int32_t {
		return C.il_router_route(r.h, ptr(envelope), C.size_t(len(envelope)), fromC, C.uint64_t(now.UnixMilli()), &line, &fwd)
	})
	d := Decision{AuditLine: string(takeBuf(&line)), Forward: takeBuf(&fwd)}
	runtime.KeepAlive(r)
	d.Verdict, d.NextHop, d.Reason = field(d.AuditLine, "verdict"), field(d.AuditLine, "next"), field(d.AuditLine, "reason")
	return d, err
}

// Close frees the router. Safe to call twice.
func (r *Router) Close() {
	if r.h != nil {
		C.il_router_free(r.h)
		r.h = nil
	}
}

func field(line, key string) string {
	for _, tok := range strings.Split(line, " ") {
		if v, ok := strings.CutPrefix(tok, key+"="); ok {
			return v
		}
	}
	return ""
}

// CBORCanonical strictly decodes CBOR and re-encodes it.
func CBORCanonical(in []byte) ([]byte, error) {
	var out C.il_buf
	err := call(func() C.int32_t { return C.il_cbor_canonical(ptr(in), C.size_t(len(in)), &out) })
	return takeBuf(&out), err
}

// CBORDiag returns RFC 8949 diagnostic notation.
func CBORDiag(in []byte) (string, error) {
	var out C.il_buf
	err := call(func() C.int32_t { return C.il_cbor_diag(ptr(in), C.size_t(len(in)), &out) })
	return string(takeBuf(&out)), err
}

// NormalizeLabel returns a label's canonical text and CBOR forms.
func NormalizeLabel(label string) (string, []byte, error) {
	l, free := cstr(label)
	defer free()
	var t, c C.il_buf
	err := call(func() C.int32_t { return C.il_label_normalize(l, &t, &c) })
	return string(takeBuf(&t)), takeBuf(&c), err
}

// SpacePacket is one CCSDS 133.0-B-2 Space Packet.
type SpacePacket struct {
	Telecommand     bool
	SecondaryHeader bool
	APID            uint16
	SequenceFlags   uint8 // 0 continuation, 1 first, 2 last, 3 unsegmented
	SequenceCount   uint16
	Data            []byte
}

func b2u(b bool) C.uint8_t {
	if b {
		return 1
	}
	return 0
}

// Encode returns the packet's octets.
func (p SpacePacket) Encode() ([]byte, error) {
	var out C.il_buf
	err := call(func() C.int32_t {
		return C.il_ccsds_packet_encode(b2u(p.Telecommand), b2u(p.SecondaryHeader), C.uint16_t(p.APID),
			C.uint8_t(p.SequenceFlags), C.uint16_t(p.SequenceCount), ptr(p.Data), C.size_t(len(p.Data)), &out)
	})
	return takeBuf(&out), err
}

// DecodeSpacePacket decodes the packet at the start of b and its length.
func DecodeSpacePacket(b []byte) (SpacePacket, int, error) {
	var tc, sec, flags C.uint8_t
	var apid, count C.uint16_t
	var used C.size_t
	var data C.il_buf
	err := call(func() C.int32_t {
		return C.il_ccsds_packet_decode(ptr(b), C.size_t(len(b)), &tc, &sec, &apid, &flags, &count, &used, &data)
	})
	p := SpacePacket{tc != 0, sec != 0, uint16(apid), uint8(flags), uint16(count), takeBuf(&data)}
	return p, int(used), err
}
