package io.github.robs96.interlingua;

/** A failure reported by the native library, with its stable identifier. */
public final class InterlinguaException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final int code;
    private final String id;

    InterlinguaException(int code, String id, String message) {
        super(message + " [" + id + "]");
        this.code = code;
        this.id = id;
    }

    /** Negative IL_E_* code. */
    public int code() {
        return code;
    }

    /** Stable identifier such as {@code BadSignature} or {@code Cbor/NonPreferredFloat}. */
    public String id() {
        return id;
    }
}
