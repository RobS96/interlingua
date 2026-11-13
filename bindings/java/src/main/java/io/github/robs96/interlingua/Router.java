package io.github.robs96.interlingua;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/** A router for one trust domain. The native router is thread-safe; close it once. */
public final class Router implements AutoCloseable {
    private final Interlingua il;
    private MemorySegment handle;

    Router(Interlingua il, MemorySegment handle) {
        this.il = il;
        this.handle = handle;
    }

    /** Decide for {@code envelope}; {@code from} is null when a local sender hands it over. */
    public synchronized Decision route(byte[] envelope, String from, long nowMs) {
        if (handle == null) {
            throw new IllegalStateException("router is closed");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment line = arena.allocate(Interlingua.IL_BUF);
            MemorySegment fwd = arena.allocate(Interlingua.IL_BUF);
            MemorySegment fromC = from == null ? MemorySegment.NULL : arena.allocateFrom(from);
            int rc = (int) il.call(il.routerRoute, handle, Interlingua.bytes(arena, envelope), Interlingua.len(envelope),
                    fromC, nowMs, line, fwd);
            String text = new String(il.take(line), StandardCharsets.UTF_8);
            byte[] forward = il.take(fwd);
            il.check(rc);
            return new Decision(field(text, "verdict"), field(text, "next"), field(text, "reason"), text, forward);
        }
    }

    static String field(String line, String key) {
        for (String token : line.split(" ")) {
            if (token.startsWith(key + "=")) {
                return token.substring(key.length() + 1);
            }
        }
        return "";
    }

    @Override
    public synchronized void close() {
        if (handle != null) {
            il.call(il.routerFree, handle);
            handle = null;
        }
    }
}
