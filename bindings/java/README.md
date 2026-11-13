# Java binding

JDK 22+ Foreign Function & Memory API: no JNI, no dependencies. Package
`io.github.robs96.interlingua`.

```java
Interlingua il = Interlingua.load(Path.of("target/release/libinterlingua_ffi.so"));
byte[][] keys = il.keygen("ground-ops");                    // {secret, public}
byte[] env = il.seal(keys[0], null, "ground-ops", "conf=low integ=low avail=low",
                     "text/plain", System.currentTimeMillis(), 60_000, 4, "hi".getBytes(UTF_8));
byte[] payload = il.open(null, keys[1], env);

try (Router r = il.router(policyText, keyring, "ground-ops")) {
    Decision d = r.route(env, null, System.currentTimeMillis());   // verdict(), nextHop(), reason()
}
```

Run with `--enable-native-access=ALL-UNNAMED` (or your module's name).
Failures throw `InterlinguaException` with a stable `id()`.

`make java` (JDK 25) compiles the sources with `javac --release 25` and runs
`Conformance`: every vector suite, then independent checks with the JDK's own
ML-DSA (JEP 497), ML-KEM (JEP 496), HKDF (JEP 510) and AES-GCM. The Java
binding is proven in CI; the layout (`src/main/java`, `src/test/java`) is
ready for a Maven or Gradle build when it is published.
