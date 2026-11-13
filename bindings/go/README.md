# Go binding

`github.com/RobS96/interlingua/bindings/go`: an idiomatic wrapper over the C
ABI (cgo, static linking). Go 1.27+.

```go
secret, public, err := interlingua.KeyGen("ground-ops")
env, err := interlingua.Seal(secret, interlingua.SealOptions{
    Dst: "ground-ops", Label: "conf=low integ=low avail=low",
    ContentType: "text/plain", Now: time.Now(), TTL: time.Minute, MaxHops: 4,
}, []byte("hi"))
payload, err := interlingua.Open(nil, public, env)

r, err := interlingua.NewRouter(policyText, keyring, "ground-ops")
defer r.Close()
d, err := r.Route(env, "", time.Now())   // d.Verdict, d.NextHop, d.Reason, d.AuditLine
```

Errors are `*interlingua.Error` with a stable `ID` (`"BadSignature"`,
`"Cbor/NonPreferredFloat"` …). Calls pin their goroutine to one OS thread while
reading the per-thread error (docs/INTEROP.md).

Build: `cargo build --release -p interlingua-ffi`, then
`CGO_LDFLAGS="$PWD/target/release/libinterlingua_ffi.a -lm" go test ./...`
(`make go` does this). The tests run every vector suite and four independent
checks with Go's standard library (`crypto/mldsa`, `crypto/mlkem`,
`crypto/hkdf`, `crypto/aes`), including an envelope built entirely in Go that
the Rust reference must open and route.
