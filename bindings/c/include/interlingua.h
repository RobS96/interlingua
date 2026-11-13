/*
 * interlingua.h: C ABI of the interlingua secure polyglot message fabric.
 *
 * ABI version 1. C is the common language every other binding goes through
 * (Swift module map, Go cgo, Java Foreign Function & Memory API), so this
 * header is the contract. Implemented in Rust (crates/interlingua-ffi).
 *
 * Rules (docs/INTEROP.md has the full model):
 *   - Functions return IL_OK (0) or a negative IL_E_* code.
 *     il_last_error_id() then gives a stable machine identifier such as
 *     "Cbor/NonPreferredFloat" or "BadSignature"; il_last_error_message()
 *     gives human text. Both are per thread.
 *   - Inputs are borrowed for the duration of the call only: byte ranges as
 *     (pointer, length), text as NUL-terminated UTF-8. NULL with length 0 is
 *     an empty range.
 *   - Outputs are il_buf values owned by the library. Every output is reset to
 *     {NULL, 0} on entry, so il_buf_free() is always safe, also after a
 *     failure, and also twice.
 *   - il_router handles are thread-safe; everything else is stateless.
 *   - The library has no clock: pass Unix milliseconds explicitly.
 */
#ifndef INTERLINGUA_H
#define INTERLINGUA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IL_ABI_VERSION 1u

/* Return codes. */
#define IL_OK                       0
#define IL_E_INVALID_ARGUMENT     (-1)
#define IL_E_CBOR                 (-10)
#define IL_E_SCHEMA               (-11)
#define IL_E_VERSION              (-12)
#define IL_E_SUITE                (-13)
#define IL_E_IDENTIFIER           (-20)
#define IL_E_LABEL                (-21)
#define IL_E_CRYPTO               (-30)
#define IL_E_BAD_SIGNATURE        (-31)
#define IL_E_UNKNOWN_SIGNER       (-32)
#define IL_E_SIGNER_NOT_AUTHORIZED (-33)
#define IL_E_DECRYPT              (-34)
#define IL_E_WRONG_RECIPIENT      (-35)
#define IL_E_KEY_REQUIRED         (-36)
#define IL_E_KEY                  (-40)
#define IL_E_POLICY               (-50)
#define IL_E_CCSDS                (-60)
#define IL_E_PANIC                (-99)

/* A byte buffer owned by the library; release it with il_buf_free(). */
typedef struct il_buf {
    uint8_t *ptr;
    size_t len;
} il_buf;

/* Opaque, thread-safe router for one trust domain. */
typedef struct il_router il_router;

/* ---- library ---------------------------------------------------------- */

uint32_t il_abi_version(void);
/* Static text, e.g. "interlingua 0.1.0 (suite IL1-CNSA2)". Do not free. */
const char *il_version(void);
/* Static name of a return code ("BadSignature", "Unknown" …). Do not free. */
const char *il_error_name(int32_t code);
int32_t il_last_error_id(il_buf *out);
int32_t il_last_error_message(il_buf *out);
void il_buf_free(il_buf *buf);

/* ---- keys and envelopes ------------------------------------------------ */

/* New ML-DSA-87 + ML-KEM-1024 keys for `domain`, as text bundles. The secret
 * bundle holds both private keys: protect it like any private key. */
int32_t il_keygen(const char *domain, il_buf *secret_out, il_buf *public_out);

/* Build, optionally seal, and sign an envelope. The source domain is the
 * secret bundle's domain. Pass a recipient public bundle (its domain must be
 * `dst`) to seal the payload with ML-KEM-1024 + AES-256-GCM, or NULL/0 for
 * plaintext. `label` is text such as "conf=moderate integ=high avail=low
 * comp=tt-c"; `content_type` a lowercase media type such as "text/plain". */
int32_t il_seal(const uint8_t *secret_bundle, size_t secret_len,
                const uint8_t *recipient_bundle, size_t recipient_len,
                const char *dst, const char *label, const char *content_type,
                uint64_t now_ms, uint64_t ttl_ms, uint8_t max_hops,
                const uint8_t *payload, size_t payload_len,
                il_buf *envelope_out);

/* IL_OK when the envelope is signed by a keyring key bound to its source. */
int32_t il_verify(const uint8_t *keyring, size_t keyring_len,
                  const uint8_t *envelope, size_t envelope_len);

/* Verify, then return the plaintext. The recipient's secret bundle may be
 * NULL/0 for plaintext envelopes. */
int32_t il_open(const uint8_t *secret_bundle, size_t secret_len,
                const uint8_t *keyring, size_t keyring_len,
                const uint8_t *envelope, size_t envelope_len,
                il_buf *payload_out);

/* One line of attr=value text describing the header. UNVERIFIED. */
int32_t il_inspect(const uint8_t *envelope, size_t envelope_len, il_buf *text_out);

/* ---- routing ------------------------------------------------------------ */

int32_t il_router_new(const char *policy_text,
                      const uint8_t *keyring, size_t keyring_len,
                      const char *node, il_router **router_out);

/* Returns IL_OK whenever a decision was made, including a rejection.
 * decision_out: the audit line ("audit seq=… verdict=forward next=relay
 * reason=ok code=0 … hash=sha384:…"). forward_out: the envelope to send on
 * when verdict=forward, empty otherwise. arrived_from: NULL when a local
 * sender handed the envelope to this router. */
int32_t il_router_route(const il_router *router,
                        const uint8_t *envelope, size_t envelope_len,
                        const char *arrived_from, uint64_t now_ms,
                        il_buf *decision_out, il_buf *forward_out);

void il_router_free(il_router *router);

/* ---- encodings ---------------------------------------------------------- */

/* Strict deterministic CBOR: decode and re-encode (identical for valid input). */
int32_t il_cbor_canonical(const uint8_t *input, size_t len, il_buf *out);
int32_t il_cbor_diag(const uint8_t *input, size_t len, il_buf *out);

/* Canonical label text and its CBOR form. */
int32_t il_label_normalize(const char *label, il_buf *text_out, il_buf *cbor_out);

/* CCSDS 133.0-B-2 Space Packets. telecommand: 0 = telemetry, 1 = telecommand. */
int32_t il_ccsds_frame(uint16_t apid, uint8_t telecommand, uint16_t first_count,
                       uint32_t max_data, const uint8_t *data, size_t len,
                       il_buf *packets_out);
int32_t il_ccsds_deframe(const uint8_t *packets, size_t len, uint32_t max_total,
                         il_buf *data_out);

/* One packet from / to its header fields. sequence_flags is the 2-bit field:
 * 0 continuation, 1 first, 2 last, 3 unsegmented. */
int32_t il_ccsds_packet_encode(uint8_t telecommand, uint8_t secondary_header,
                               uint16_t apid, uint8_t sequence_flags,
                               uint16_t sequence_count,
                               const uint8_t *data, size_t len, il_buf *packet_out);
int32_t il_ccsds_packet_decode(const uint8_t *bytes, size_t len,
                               uint8_t *telecommand_out, uint8_t *secondary_header_out,
                               uint16_t *apid_out, uint8_t *sequence_flags_out,
                               uint16_t *sequence_count_out, size_t *consumed_out,
                               il_buf *data_out);

/* SHA-384 (key identifiers are SHA-384 of the raw public key). */
int32_t il_sha384(const uint8_t *input, size_t len, il_buf *out);

#ifdef __cplusplus
}
#endif

#endif /* INTERLINGUA_H */
