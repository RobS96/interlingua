# interlingua: build and prove every binding against the same vectors.
#
#   make            Rust build + tests + every local binding
#   make rust       cargo fmt --check, clippy -D warnings, tests
#   make c          C conformance under AddressSanitizer + UBSan
#   make go         Go (cgo) conformance
#   make swift      Swift conformance + Apple CryptoKit cross-checks
#   make java       Java (FFM) conformance + JDK cross-checks (needs JDK 25)
#   make openssl    OpenSSL cross-checks (ML-DSA-87, ML-KEM-1024, HKDF)
#   make vectors    il vectors check spec/vectors
#   make supply     cargo deny + cargo vet
#
# POSIX make; no recipe depends on the shell's environment beyond PATH.

CARGO_TARGET_DIR ?= $(CURDIR)/target
export CARGO_TARGET_DIR
PROFILE   ?= debug
CARGOFLAGS ?= --locked
LIBDIR    = $(CARGO_TARGET_DIR)/$(PROFILE)
STATICLIB = $(LIBDIR)/libinterlingua_ffi.a
VECTORS   = $(CURDIR)/spec/vectors
UNAME    := $(shell uname -s)

ifeq ($(UNAME),Darwin)
# One deployment target for Rust, AWS-LC's C/assembly, the C test and Swift
# (Package.swift says .macOS(.v13)); CryptoKit's ML-DSA/ML-KEM checks are
# gated at run time on macOS 26.
MACOSX_DEPLOYMENT_TARGET ?= 13.0
export MACOSX_DEPLOYMENT_TARGET
NATIVE_LIBS = -lSystem -lc -lm
SHARED_EXT  = dylib
else
NATIVE_LIBS = -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
SHARED_EXT  = so
endif

CFLAGS ?= -std=c11 -Wall -Wextra -Werror -pedantic -O1 -g -fno-omit-frame-pointer \
          -fsanitize=address,undefined -fno-sanitize-recover=all

.PHONY: all rust lib c go swift java openssl vectors supply clean

all: rust c go swift vectors

rust:
	cargo fmt --all --check
	cargo clippy $(CARGOFLAGS) --workspace --all-targets -- -D warnings
	cargo test $(CARGOFLAGS) --workspace

lib:
	cargo build $(CARGOFLAGS) -p interlingua-ffi -p interlingua-cli

c: lib
	mkdir -p $(CARGO_TARGET_DIR)/c
	$(CC) $(CFLAGS) -Ibindings/c/include bindings/c/tests/conformance.c \
	  $(STATICLIB) $(NATIVE_LIBS) -o $(CARGO_TARGET_DIR)/c/conformance
	$(CARGO_TARGET_DIR)/c/conformance $(VECTORS)

# local: use the installed Go (1.27+). CI sets auto, which fetches the go.mod
# toolchain through Go's checksum-verified toolchain download.
GOTOOLCHAIN ?= local
go: lib
	cd bindings/go && CGO_ENABLED=1 GOTOOLCHAIN=$(GOTOOLCHAIN) \
	  CGO_LDFLAGS="$(STATICLIB) $(NATIVE_LIBS)" \
	  INTERLINGUA_VECTORS=$(VECTORS) go test -count=1 ./...

# SWIFTFLAGS: extra SwiftPM flags, e.g. --disable-sandbox when already sandboxed.
SWIFTFLAGS ?=
swift: lib
	cd bindings/swift && swift build $(SWIFTFLAGS) -Xlinker $(STATICLIB) && \
	  swift run $(SWIFTFLAGS) -Xlinker $(STATICLIB) interlingua-conformance $(VECTORS)

java:
	cargo build $(CARGOFLAGS) -p interlingua-ffi
	rm -rf bindings/java/out && mkdir -p bindings/java/out
	javac --release 25 -d bindings/java/out \
	  bindings/java/src/main/java/io/github/robs96/interlingua/*.java \
	  bindings/java/src/test/java/io/github/robs96/interlingua/*.java
	java --enable-native-access=ALL-UNNAMED -cp bindings/java/out \
	  io.github.robs96.interlingua.Conformance $(LIBDIR)/libinterlingua_ffi.$(SHARED_EXT) $(VECTORS)

openssl: lib
	scripts/crosscheck-openssl.sh $(LIBDIR)/il $(VECTORS)

vectors: lib
	$(LIBDIR)/il vectors check $(VECTORS)

supply:
	cargo deny check
	cargo vet check $(CARGOFLAGS)

clean:
	cargo clean
	rm -rf bindings/swift/.build bindings/java/out
