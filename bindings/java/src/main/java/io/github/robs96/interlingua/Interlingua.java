package io.github.robs96.interlingua;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * Java binding of the interlingua C ABI through the Foreign Function &amp; Memory
 * API (JDK 22+, no JNI, no dependencies).
 *
 * <p>Load the native library once with {@link #load(Path)}; run the JVM with
 * {@code --enable-native-access=ALL-UNNAMED} (or the module's name). Every
 * call copies its inputs into a confined arena, calls the library, copies the
 * outputs back and frees them, so no native memory outlives a call. Errors
 * are reported per OS thread, so each method reads the error immediately
 * after the failing call with no blocking in between (safe for platform and
 * virtual threads).
 */
public final class Interlingua {
    private static final Linker LINKER = Linker.nativeLinker();
    static final ValueLayout SIZE_T = (ValueLayout) LINKER.canonicalLayouts().get("size_t");
    /** {@code struct il_buf { uint8_t *ptr; size_t len; }} */
    static final StructLayout IL_BUF = MemoryLayout.structLayout(ADDRESS.withName("ptr"), SIZE_T.withName("len"));

    private final SymbolLookup lookup;
    final MethodHandle version, abiVersion, lastErrorId, lastErrorMessage, bufFree, keygen, seal, verify, open,
            routerNew, routerRoute, routerFree, cborCanonical, cborDiag, labelNormalize, packetEncode, packetDecode;

    private Interlingua(SymbolLookup lookup) {
        this.lookup = lookup;
        version = handle("il_version", FunctionDescriptor.of(ADDRESS));
        abiVersion = handle("il_abi_version", FunctionDescriptor.of(JAVA_INT));
        lastErrorId = handle("il_last_error_id", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        lastErrorMessage = handle("il_last_error_message", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        bufFree = handle("il_buf_free", FunctionDescriptor.ofVoid(ADDRESS));
        keygen = handle("il_keygen", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        seal = handle("il_seal", FunctionDescriptor.of(JAVA_INT, ADDRESS, SIZE_T, ADDRESS, SIZE_T, ADDRESS, ADDRESS,
                ADDRESS, JAVA_LONG, JAVA_LONG, JAVA_BYTE, ADDRESS, SIZE_T, ADDRESS));
        verify = handle("il_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, SIZE_T, ADDRESS, SIZE_T));
        open = handle("il_open", FunctionDescriptor.of(JAVA_INT, ADDRESS, SIZE_T, ADDRESS, SIZE_T, ADDRESS, SIZE_T, ADDRESS));
        routerNew = handle("il_router_new", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, SIZE_T, ADDRESS, ADDRESS));
        routerRoute = handle("il_router_route", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, SIZE_T, ADDRESS, JAVA_LONG,
                ADDRESS, ADDRESS));
        routerFree = handle("il_router_free", FunctionDescriptor.ofVoid(ADDRESS));
        cborCanonical = handle("il_cbor_canonical", FunctionDescriptor.of(JAVA_INT, ADDRESS, SIZE_T, ADDRESS));
        cborDiag = handle("il_cbor_diag", FunctionDescriptor.of(JAVA_INT, ADDRESS, SIZE_T, ADDRESS));
        labelNormalize = handle("il_label_normalize", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        packetEncode = handle("il_ccsds_packet_encode", FunctionDescriptor.of(JAVA_INT, JAVA_BYTE, JAVA_BYTE, JAVA_SHORT,
                JAVA_BYTE, JAVA_SHORT, ADDRESS, SIZE_T, ADDRESS));
        packetDecode = handle("il_ccsds_packet_decode", FunctionDescriptor.of(JAVA_INT, ADDRESS, SIZE_T, ADDRESS, ADDRESS,
                ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    }

    /** Load the native library (for example {@code target/release/libinterlingua_ffi.dylib}). */
    public static Interlingua load(Path library) {
        Interlingua il = new Interlingua(SymbolLookup.libraryLookup(library, Arena.global()));
        int abi = (int) il.call(il.abiVersion);
        if (abi != 1) {
            throw new IllegalStateException("native library has ABI " + abi + ", this binding expects 1");
        }
        return il;
    }

    private MethodHandle handle(String name, FunctionDescriptor descriptor) {
        MemorySegment symbol = lookup.find(name)
                .orElseThrow(() -> new IllegalStateException("native library lacks " + name));
        return LINKER.downcallHandle(symbol, descriptor);
    }

    Object call(MethodHandle h, Object... args) {
        try {
            return h.invokeWithArguments(args);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    static MemorySegment bytes(Arena arena, byte[] data) {
        return data == null || data.length == 0 ? MemorySegment.NULL : arena.allocateFrom(JAVA_BYTE, data);
    }

    static long len(byte[] data) {
        return data == null ? 0 : data.length;
    }

    /** Copy a library buffer out and free it. */
    byte[] take(MemorySegment buf) {
        MemorySegment ptr = buf.get(ADDRESS, 0);
        long n = SIZE_T.byteSize() == 8 ? buf.get(JAVA_LONG, ADDRESS.byteSize()) : buf.get(JAVA_INT, ADDRESS.byteSize());
        byte[] out = (ptr.address() == 0 || n == 0) ? new byte[0] : ptr.reinterpret(n).toArray(JAVA_BYTE);
        call(bufFree, buf);
        return out;
    }

    /** Throw the thread's last error when {@code rc} is not IL_OK. */
    void check(int rc) {
        if (rc == 0) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment id = arena.allocate(IL_BUF);
            MemorySegment msg = arena.allocate(IL_BUF);
            call(lastErrorId, id);
            call(lastErrorMessage, msg);
            throw new InterlinguaException(rc, new String(take(id), StandardCharsets.UTF_8),
                    new String(take(msg), StandardCharsets.UTF_8));
        }
    }

    /** The native library's version text. */
    public String version() {
        MemorySegment s = (MemorySegment) call(version);
        return s.reinterpret(Long.MAX_VALUE).getString(0);
    }

    /** New keys for {@code domain}: {secret bundle, public bundle}. */
    public byte[][] keygen(String domain) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = arena.allocate(IL_BUF);
            MemorySegment p = arena.allocate(IL_BUF);
            int rc = (int) call(keygen, arena.allocateFrom(domain), s, p);
            byte[][] out = {take(s), take(p)};
            check(rc);
            return out;
        }
    }

    /** Build, optionally seal ({@code recipient} = its public bundle), and sign an envelope. */
    public byte[] seal(byte[] secret, byte[] recipient, String dst, String label, String contentType, long nowMs,
            long ttlMs, int maxHops, byte[] payload) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(IL_BUF);
            int rc = (int) call(seal, bytes(arena, secret), len(secret), bytes(arena, recipient), len(recipient),
                    arena.allocateFrom(dst), arena.allocateFrom(label), arena.allocateFrom(contentType), nowMs, ttlMs,
                    (byte) maxHops, bytes(arena, payload), len(payload), out);
            byte[] envelope = take(out);
            check(rc);
            return envelope;
        }
    }

    /** Throws unless a keyring key bound to the source domain signed the envelope. */
    public void verify(byte[] keyring, byte[] envelope) {
        try (Arena arena = Arena.ofConfined()) {
            check((int) call(verify, bytes(arena, keyring), len(keyring), bytes(arena, envelope), len(envelope)));
        }
    }

    /** Verify, then return the plaintext ({@code secret} = the recipient's bundle, or null). */
    public byte[] open(byte[] secret, byte[] keyring, byte[] envelope) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(IL_BUF);
            int rc = (int) call(open, bytes(arena, secret), len(secret), bytes(arena, keyring), len(keyring),
                    bytes(arena, envelope), len(envelope), out);
            byte[] payload = take(out);
            check(rc);
            return payload;
        }
    }

    /** Strict deterministic CBOR: decode and re-encode. */
    public byte[] cborCanonical(byte[] input) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(IL_BUF);
            int rc = (int) call(cborCanonical, bytes(arena, input), len(input), out);
            byte[] bytes = take(out);
            check(rc);
            return bytes;
        }
    }

    /** RFC 8949 diagnostic notation. */
    public String cborDiag(byte[] input) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(IL_BUF);
            int rc = (int) call(cborDiag, bytes(arena, input), len(input), out);
            String text = new String(take(out), StandardCharsets.UTF_8);
            check(rc);
            return text;
        }
    }

    /** Canonical label: {canonical text (UTF-8), CBOR}. */
    public byte[][] normalizeLabel(String label) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(IL_BUF);
            MemorySegment cbor = arena.allocate(IL_BUF);
            int rc = (int) call(labelNormalize, arena.allocateFrom(label), text, cbor);
            byte[][] out = {take(text), take(cbor)};
            check(rc);
            return out;
        }
    }

    /** Encode one CCSDS Space Packet. */
    public byte[] encodePacket(SpacePacket p) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(IL_BUF);
            int rc = (int) call(packetEncode, (byte) (p.telecommand() ? 1 : 0), (byte) (p.secondaryHeader() ? 1 : 0),
                    (short) p.apid(), (byte) p.sequenceFlags(), (short) p.sequenceCount(), bytes(arena, p.data()),
                    len(p.data()), out);
            byte[] packet = take(out);
            check(rc);
            return packet;
        }
    }

    /** Decode the CCSDS Space Packet at the start of {@code bytes}. */
    public SpacePacket decodePacket(byte[] bytes) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment tc = arena.allocate(JAVA_BYTE), sec = arena.allocate(JAVA_BYTE), flags = arena.allocate(JAVA_BYTE);
            MemorySegment apid = arena.allocate(JAVA_SHORT), count = arena.allocate(JAVA_SHORT);
            MemorySegment used = arena.allocate(SIZE_T);
            MemorySegment data = arena.allocate(IL_BUF);
            int rc = (int) call(packetDecode, bytes(arena, bytes), len(bytes), tc, sec, apid, flags, count, used, data);
            byte[] payload = take(data);
            check(rc);
            long consumed = SIZE_T.byteSize() == 8 ? used.get(JAVA_LONG, 0) : used.get(JAVA_INT, 0);
            return new SpacePacket(tc.get(JAVA_BYTE, 0) != 0, sec.get(JAVA_BYTE, 0) != 0,
                    Short.toUnsignedInt(apid.get(JAVA_SHORT, 0)), Byte.toUnsignedInt(flags.get(JAVA_BYTE, 0)),
                    Short.toUnsignedInt(count.get(JAVA_SHORT, 0)), payload, (int) consumed);
        }
    }

    /** A router for one trust domain; close it when done. */
    public Router router(String policy, byte[] keyring, String node) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(ADDRESS);
            int rc = (int) call(routerNew, arena.allocateFrom(policy), bytes(arena, keyring), len(keyring),
                    arena.allocateFrom(node), out);
            check(rc);
            return new Router(this, out.get(ADDRESS, 0));
        }
    }
}
