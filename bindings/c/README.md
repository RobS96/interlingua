# C binding

The C ABI is the contract every other binding builds on:
[`include/interlingua.h`](include/interlingua.h) (ABI version 1).

```c
#include "interlingua.h"

il_buf secret = {0}, public_ = {0}, env = {0};
il_keygen("ground-ops", &secret, &public_);
int32_t rc = il_seal(secret.ptr, secret.len, NULL, 0, "ground-ops",
                     "conf=low integ=low avail=low", "text/plain",
                     now_ms, 60000, 4, (const uint8_t *)"hi", 2, &env);
if (rc != IL_OK) { il_buf id = {0}; il_last_error_id(&id); /* … */ il_buf_free(&id); }
il_buf_free(&env); il_buf_free(&public_); il_buf_free(&secret);
```

Rules (also in the header): `0` or a negative `IL_E_*` code; inputs borrowed
for the call; outputs owned by the library and released with `il_buf_free`
(always safe, also after a failure or twice); errors per thread; routers
thread-safe.

Build and link (static):

```bash
cargo build --release -p interlingua-ffi
cc -std=c11 -Ibindings/c/include app.c target/release/libinterlingua_ffi.a -lm   # Linux: add -lpthread -ldl
```

`make c` builds [`tests/conformance.c`](tests/conformance.c), which runs all
five vector suites under AddressSanitizer and UBSan.
