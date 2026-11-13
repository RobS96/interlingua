# Language interoperability guide

How interlingua stays identical across Rust, C, Swift, Go and Java, and the
cross-language details that usually break that promise.

## 1. The interlingua method

Two ways to make N languages exchange data:

* **Pairwise transfer**: each pair agrees on its own conversion:
  N×(N−1)/2 converters (10 for five languages), each one a place to drift.
* **Interlingua**: every language converts to and from one canonical form:
  N codecs, and each is checked against the same test vectors.

interlingua goes one step further: the codec exists **once**, in Rust,
behind a C ABI, and each language binding is a thin wrapper over it. A
binding can therefore only disagree with another through its wrapper, and the
shared vectors check exactly that. Independent re-implementations of the
cryptography (Go standard library, Apple CryptoKit, the JDK, OpenSSL) then
check the *specification* rather than the code.

## 2. The C ABI contract

| Rule | Why |
|---|---|
| Return `0` or a negative code; never unwind across the boundary | C has no exceptions; a Rust panic crossing into C is undefined behaviour, so panics are caught and reported as `IL_E_PANIC` |
| Inputs are `(const uint8_t *, size_t)` or NUL-terminated UTF-8, borrowed for the call | no ownership transfer into the library, no lifetime questions |
| Outputs are `il_buf {uint8_t *ptr; size_t len}` owned by the library, freed with `il_buf_free` | one allocator owns each buffer; mixing `free()` and Rust's allocator is undefined behaviour |
| Every output is reset to `{NULL, 0}` on entry; `il_buf_free` is idempotent | freeing after a failure, or twice, is always safe |
| `il_router` is opaque and thread-safe | handles are the only state that crosses the boundary |
| `IL_ABI_VERSION` / `il_abi_version()` | bindings refuse a library with a different ABI |

### Errors across threads

The last error is kept **per OS thread** (like `errno`), and read with
`il_last_error_id` / `il_last_error_message` straight after the failing call.
Languages that move work between threads must keep both calls on one thread:

| Language | How the binding guarantees it |
|---|---|
| Go | `runtime.LockOSThread()` around the call and the error read (goroutines migrate between threads) |
| Java | the two downcalls run back to back with no blocking in between, so a virtual thread stays mounted on one carrier |
| Swift | the calls are synchronous; no `await` between them |
| C | nothing needed |

## 3. Type mapping

| Concept | C | Rust | Swift | Go | Java (FFM) |
|---|---|---|---|---|---|
| byte range in | `const uint8_t *, size_t` | `&[u8]` | `Data` | `[]byte` | `byte[]` → `MemorySegment` |
| buffer out | `il_buf *` | `Vec<u8>` | `Data` | `[]byte` | `byte[]` |
| text in | `const char *` (UTF-8) | `&str` | `String` | `string` | `String` (`allocateFrom` = UTF-8) |
| time | `uint64_t` ms | `u64` | `UInt64` | `time.Time` | `long` |
| router | `il_router *` | `Router` | `final class Router` | `*Router` | `Router implements AutoCloseable` |
| error | `int32_t` + id | `Error` enum | `InterlinguaError` | `*Error` | `InterlinguaException` |
| `size_t` | 64-bit on supported targets | `usize` | `Int` | `C.size_t` | `canonicalLayouts().get("size_t")` |

Unsigned narrow integers (`uint8_t` hop counts, `uint16_t` APIDs) map to
Java's signed `byte` and `short`; the binding converts with
`Byte.toUnsignedInt` / `Short.toUnsignedInt` on the way out. All supported
values are below the sign bit anyway.

## 4. Numbers, text and time

* **IEEE 754.** Headers contain no floating-point values, so no two languages
  can format or round them differently. Payload schemas that do use floats
  get deterministic CBOR's rule: shortest exact width (binary16 → binary32 →
  binary64), `-0.0` preserved, one NaN (`0xf97e00`). The CBOR vectors pin
  this down to the bit, including subnormal binary16 values.
* **Integers** are unsigned 64-bit on the wire. Negative CBOR integers are
  `-1 - n`, so `-2^64` is representable; Rust prints it via 128-bit
  arithmetic, and other languages should do the same or use big integers.
* **Text** is UTF-8 (the encoding Ken Thompson and Rob Pike designed for
  Plan 9 at Bell Labs). Identifiers are lowercase ASCII, so equality is
  bytewise and no normalization (NFC/NFD) or confusable check is ever needed.
  Payload text should be UTF-8 without a BOM; the vectors include Greek,
  Japanese, mathematical and emoji text.
* **Time** is Unix milliseconds in UTC, leap seconds not counted, carried as
  an unsigned integer. Space missions that keep TAI or CCSDS time codes
  (CUC/CDS) convert at the edge; the router only needs comparisons within the
  configured clock skew.
* **Byte order** is defined by CBOR (big-endian heads) and CCSDS (big-endian
  fields); no binding ever writes host-order integers.

## 5. Per-language notes

* **C**: link the static library and the platform's system libraries
  (`-lSystem -lc -lm` on macOS; `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc`
  on Linux). The conformance runner builds with `-Wall -Wextra -Werror
  -pedantic` under AddressSanitizer and UBSan.
* **Swift**: `CInterlingua` is a system-library module over the shared
  header; `Interlingua` is the Swift API; Swift 6 strict concurrency
  (`Router` is `@unchecked Sendable` because the native router is
  thread-safe). CryptoKit's ML-DSA and ML-KEM need macOS / iOS 26; the
  cross-checks are gated with `#available`.
* **Go**: cgo with the header from `bindings/c/include`; link flags come from
  `CGO_LDFLAGS`; `Router` has a finalizer as a safety net, but call `Close`.
* **Java**: the FFM API (final in JDK 22), no JNI and no dependencies; run
  with `--enable-native-access=ALL-UNNAMED` (or the module's name). Each call
  uses a confined `Arena`, so no native memory outlives it.

## 6. Proving a new binding

1. Wrap the C ABI functions you need, following section 2.
2. Parse the `.rsp` files (twenty lines in any language) and run all five
   suites; the C, Go, Swift and Java runners are templates.
3. Where the language has its own cryptography, add independent checks:
   derive the ML-DSA-87 keys from the published seeds, verify the vector
   signatures, re-derive HKDF and AES-GCM from the sealed vector's
   intermediates, and if possible build a whole envelope and have the
   reference open it.
4. Add the binding to CI and to the table in the README.
