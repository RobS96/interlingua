//! Stable C ABI for interlingua (`bindings/c/include/interlingua.h`).
//!
//! This is the one crate in the workspace that may use `unsafe`, and only to
//! turn C pointers into Rust slices and strings and back. The rules every
//! function follows (see `docs/INTEROP.md`):
//!
//! * Return `IL_OK` (0) or a negative `IL_E_*` code; never unwind into C
//!   (panics are caught and reported as `IL_E_PANIC`).
//! * Inputs are `(pointer, length)` byte ranges or NUL-terminated UTF-8
//!   strings, borrowed for the duration of the call only.
//! * Outputs are `il_buf` values allocated here and released with
//!   `il_buf_free`; every output is reset to `{NULL, 0}` on entry, so freeing
//!   after a failure is always safe.
//! * The thread's last error is available through `il_last_error_id` (stable
//!   machine identifier) and `il_last_error_message` (human text).
//! * `il_router` handles are thread-safe: decisions are serialized inside.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)] // the safety contract is documented once, above and in the header

use std::cell::RefCell;
use std::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use interlingua::ccsds::{self, PacketType};
use interlingua::envelope::{self, Draft};
use interlingua::{
    Envelope, Error, Keyring, Label, Policy, PublicKeys, Router, SecretKeys, cbor, crypto, hex,
    uuid7,
};

/// Success.
pub const IL_OK: i32 = 0;
/// A Rust panic was caught at the boundary (a bug).
pub const IL_E_PANIC: i32 = -99;
/// Version of this C ABI. Additions keep the number; changes bump it.
pub const IL_ABI_VERSION: u32 = 1;

/// A byte buffer owned by the library. Free it with `il_buf_free`.
#[repr(C)]
#[derive(Debug)]
pub struct IlBuf {
    /// Start of the bytes, or NULL when empty.
    pub ptr: *mut u8,
    /// Number of bytes.
    pub len: usize,
}

/// Opaque router handle.
#[derive(Debug)]
pub struct IlRouter {
    router: Router,
}

thread_local! {
    static LAST_ERROR: RefCell<(String, String)> = const { RefCell::new((String::new(), String::new())) };
}

fn remember(id: String, message: String) {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = (id, message));
}

/// Run `f`, turning errors and panics into codes and recording the last error.
fn guard(f: impl FnOnce() -> Result<(), Error>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {
            remember(String::new(), String::new());
            IL_OK
        }
        Ok(Err(e)) => {
            remember(e.id(), e.to_string());
            e.code()
        }
        Err(_) => {
            remember(
                "Panic".into(),
                "internal panic caught at the C boundary (a bug)".into(),
            );
            IL_E_PANIC
        }
    }
}

/// Borrow `(ptr, len)` as a slice.
///
/// # Safety
/// `ptr` must point to `len` readable bytes that stay valid and unchanged for
/// the call (or `len` must be 0).
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], Error> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Error::InvalidArgument(
            "NULL pointer with a non-zero length",
        ));
    }
    if isize::try_from(len).is_err() {
        return Err(Error::InvalidArgument("length is larger than isize::MAX"));
    }
    // SAFETY: non-null, length bounded by isize::MAX, readable per the caller's contract.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Borrow a NUL-terminated UTF-8 string; NULL gives `None`.
///
/// # Safety
/// `ptr` must be NULL or point to a NUL-terminated string valid for the call.
unsafe fn opt_text<'a>(ptr: *const c_char) -> Result<Option<&'a str>, Error> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null and NUL-terminated per the caller's contract.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str()
        .map(Some)
        .map_err(|_| Error::InvalidArgument("string is not valid UTF-8"))
}

/// Borrow a required NUL-terminated UTF-8 string.
///
/// # Safety
/// As [`opt_text`].
unsafe fn text<'a>(ptr: *const c_char, what: &'static str) -> Result<&'a str, Error> {
    // SAFETY: same contract as opt_text.
    unsafe { opt_text(ptr) }?.ok_or(Error::InvalidArgument(what))
}

/// Reset an output buffer to empty.
///
/// # Safety
/// `out` must be NULL or point to writable `IlBuf` storage.
unsafe fn clear(out: *mut IlBuf) {
    if !out.is_null() {
        // SAFETY: non-null and writable per the caller's contract. Writing does not
        // read (or free) whatever was there.
        unsafe {
            out.write(IlBuf {
                ptr: ptr::null_mut(),
                len: 0,
            });
        }
    }
}

/// Hand `data` to the caller through `out`.
///
/// # Safety
/// `out` must be NULL (an error) or point to writable `IlBuf` storage.
unsafe fn give(out: *mut IlBuf, data: Vec<u8>) -> Result<(), Error> {
    if out.is_null() {
        return Err(Error::InvalidArgument("output buffer pointer is NULL"));
    }
    let buf = if data.is_empty() {
        IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        }
    } else {
        let boxed = data.into_boxed_slice();
        let len = boxed.len();
        IlBuf {
            ptr: Box::into_raw(boxed).cast::<u8>(),
            len,
        }
    };
    // SAFETY: non-null and writable per the caller's contract.
    unsafe { out.write(buf) };
    Ok(())
}

/// The ABI version (1).
#[unsafe(no_mangle)]
pub extern "C" fn il_abi_version() -> u32 {
    IL_ABI_VERSION
}

static VERSION_TEXT: &str = concat!(
    "interlingua ",
    env!("CARGO_PKG_VERSION"),
    " (suite IL1-CNSA2)\0"
);
static VERSION_TEXT_FIPS: &str = concat!(
    "interlingua ",
    env!("CARGO_PKG_VERSION"),
    " (suite IL1-CNSA2, AWS-LC FIPS module)\0"
);

/// Static, NUL-terminated library version text.
#[unsafe(no_mangle)]
pub extern "C" fn il_version() -> *const c_char {
    let text = if interlingua::fips_build() {
        VERSION_TEXT_FIPS
    } else {
        VERSION_TEXT
    };
    text.as_ptr().cast::<c_char>()
}

/// Static, NUL-terminated name of an error code (`"BadSignature"`, …).
#[unsafe(no_mangle)]
pub extern "C" fn il_error_name(code: i32) -> *const c_char {
    let name: &CStr = match Error::name_for_code(code) {
        "Ok" => c"Ok",
        "InvalidArgument" => c"InvalidArgument",
        "Cbor" => c"Cbor",
        "Schema" => c"Schema",
        "Version" => c"Version",
        "Suite" => c"Suite",
        "Identifier" => c"Identifier",
        "Label" => c"Label",
        "Crypto" => c"Crypto",
        "BadSignature" => c"BadSignature",
        "UnknownSigner" => c"UnknownSigner",
        "SignerNotAuthorized" => c"SignerNotAuthorized",
        "Decrypt" => c"Decrypt",
        "WrongRecipient" => c"WrongRecipient",
        "KeyRequired" => c"KeyRequired",
        "Key" => c"Key",
        "Policy" => c"Policy",
        "Ccsds" => c"Ccsds",
        "Vector" => c"Vector",
        "Panic" => c"Panic",
        _ => c"Unknown",
    };
    name.as_ptr()
}

/// Copy the calling thread's last error identifier (`"Cbor/NonPreferredFloat"`)
/// into `out` (empty after a success).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_last_error_id(out: *mut IlBuf) -> i32 {
    let id = LAST_ERROR.with(|cell| cell.borrow().0.clone());
    // SAFETY: caller contract for `out`.
    unsafe { clear(out) };
    // Not wrapped in `guard`: that would overwrite the error being read.
    // SAFETY: caller contract for `out`.
    match unsafe { give(out, id.into_bytes()) } {
        Ok(()) => IL_OK,
        Err(e) => e.code(),
    }
}

/// Copy the calling thread's last error message into `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_last_error_message(out: *mut IlBuf) -> i32 {
    let message = LAST_ERROR.with(|cell| cell.borrow().1.clone());
    // SAFETY: caller contract for `out`.
    unsafe { clear(out) };
    // SAFETY: caller contract for `out`.
    match unsafe { give(out, message.into_bytes()) } {
        Ok(()) => IL_OK,
        Err(e) => e.code(),
    }
}

/// Release a buffer from this library and reset it to `{NULL, 0}`.
/// Safe to call on an empty buffer and to call twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_buf_free(buf: *mut IlBuf) {
    if buf.is_null() {
        return;
    }
    // SAFETY: non-null, and the caller passes a buffer this library filled (or emptied).
    let b = unsafe { &mut *buf };
    if !b.ptr.is_null() && b.len > 0 {
        let slice = ptr::slice_from_raw_parts_mut(b.ptr, b.len);
        // SAFETY: (ptr, len) came from Box<[u8]>::into_raw in `give` and is freed
        // exactly once, because the fields are reset below.
        drop(unsafe { Box::from_raw(slice) });
    }
    b.ptr = ptr::null_mut();
    b.len = 0;
}

/// Generate keys for `domain`: a secret bundle and the matching public bundle
/// (UTF-8 text, see `docs/OPERATIONS.md`). The secret bundle holds both private
/// keys; store it like any private key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_keygen(
    domain: *const c_char,
    secret_out: *mut IlBuf,
    public_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for both outputs.
    unsafe {
        clear(secret_out);
        clear(public_out);
    }
    guard(|| {
        // SAFETY: caller contract for `domain`.
        let domain = unsafe { text(domain, "domain is NULL") }?;
        let keys = SecretKeys::generate(domain)?;
        let secret = keys.to_text()?;
        // SAFETY: caller contract for both outputs.
        unsafe {
            give(secret_out, secret.as_bytes().to_vec())?;
            give(public_out, keys.public().to_text().into_bytes())
        }
    })
}

/// Build and sign an envelope from the sender's secret bundle. With a
/// recipient public bundle the payload is sealed to it (its domain must be
/// `dst`); with NULL/0 the payload travels in plaintext. The source domain is
/// the secret bundle's domain: a sender can only speak for itself.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_seal(
    secret_bundle: *const u8,
    secret_len: usize,
    recipient_bundle: *const u8,
    recipient_len: usize,
    dst: *const c_char,
    label: *const c_char,
    content_type: *const c_char,
    now_ms: u64,
    ttl_ms: u64,
    max_hops: u8,
    payload: *const u8,
    payload_len: usize,
    envelope_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(envelope_out) };
    guard(|| {
        // SAFETY: caller contract for every input pointer.
        let (secret, recipient, dst, label, content_type, payload) = unsafe {
            (
                bytes(secret_bundle, secret_len)?,
                bytes(recipient_bundle, recipient_len)?,
                text(dst, "dst is NULL")?,
                text(label, "label is NULL")?,
                text(content_type, "content type is NULL")?,
                bytes(payload, payload_len)?,
            )
        };
        let sender = SecretKeys::parse(utf8(secret)?)?;
        let recipient = if recipient.is_empty() {
            None
        } else {
            let keys = PublicKeys::parse(utf8(recipient)?)?;
            if keys.domain != dst {
                return Err(Error::InvalidArgument(
                    "recipient keys belong to a domain other than dst",
                ));
            }
            Some(keys)
        };
        let draft = Draft {
            src: &sender.domain,
            dst,
            label: Label::parse(label)?,
            content_type,
            ttl_ms,
            max_hops,
            payload,
        };
        let ek = recipient.as_ref().map(|k| k.encapsulation_key.as_slice());
        let wire = envelope::seal_and_sign(&draft, &sender.signing, ek, now_ms)?.encode()?;
        // SAFETY: caller contract for the output.
        unsafe { give(envelope_out, wire) }
    })
}

fn utf8(raw: &[u8]) -> Result<&str, Error> {
    core::str::from_utf8(raw).map_err(|_| Error::Key("key text is not UTF-8"))
}

/// Verify an envelope's signature against a keyring (concatenated public
/// bundles). `IL_OK` means authentic: a known key, bound to the source domain,
/// signed exactly these bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_verify(
    keyring: *const u8,
    keyring_len: usize,
    envelope: *const u8,
    envelope_len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: caller contract for both inputs.
        let (ring, env) = unsafe { (bytes(keyring, keyring_len)?, bytes(envelope, envelope_len)?) };
        let ring = Keyring::parse(utf8(ring)?)?;
        Envelope::decode(env)?.verify(&ring).map(|_| ())
    })
}

/// Verify, then return the plaintext payload. `secret_bundle` (the
/// recipient's) may be NULL/0 for plaintext envelopes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_open(
    secret_bundle: *const u8,
    secret_len: usize,
    keyring: *const u8,
    keyring_len: usize,
    envelope: *const u8,
    envelope_len: usize,
    payload_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(payload_out) };
    guard(|| {
        // SAFETY: caller contract for every input.
        let (secret, ring, env) = unsafe {
            (
                bytes(secret_bundle, secret_len)?,
                bytes(keyring, keyring_len)?,
                bytes(envelope, envelope_len)?,
            )
        };
        let ring = Keyring::parse(utf8(ring)?)?;
        let recipient = if secret.is_empty() {
            None
        } else {
            Some(SecretKeys::parse(utf8(secret)?)?)
        };
        let payload = Envelope::decode(env)?
            .verify_and_open(&ring, recipient.as_ref().map(|k| &k.decapsulation))?;
        // SAFETY: caller contract for the output.
        unsafe { give(payload_out, payload) }
    })
}

/// Describe an envelope's header as one line of `attr=value` text, without
/// verifying it (for logs and debugging only: nothing in it is trusted).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_inspect(
    envelope: *const u8,
    envelope_len: usize,
    text_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(text_out) };
    guard(|| {
        // SAFETY: caller contract for the input.
        let env = Envelope::decode(unsafe { bytes(envelope, envelope_len) }?)?;
        let h = &env.header;
        let comp: Vec<&str> = h.label.compartments.iter().map(String::as_str).collect();
        let line = format!(
            "id={} src={} dst={} conf={} integ={} avail={} comp={} created={} expires={} max-hops={} hops={} type={} sealed={} signer=sha384:{}",
            uuid7::format(&h.id),
            h.src,
            h.dst,
            h.label.confidentiality,
            h.label.integrity,
            h.label.availability,
            if comp.is_empty() {
                "-".to_owned()
            } else {
                comp.join(",")
            },
            h.created_ms,
            h.expires_ms,
            h.max_hops,
            env.hops,
            h.content_type,
            if h.sealed { "yes" } else { "no" },
            hex::encode(&h.signer),
        );
        // SAFETY: caller contract for the output.
        unsafe { give(text_out, line.into_bytes()) }
    })
}

/// Create a router for `node` from policy text and a keyring.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_router_new(
    policy_text: *const c_char,
    keyring: *const u8,
    keyring_len: usize,
    node: *const c_char,
    router_out: *mut *mut IlRouter,
) -> i32 {
    if !router_out.is_null() {
        // SAFETY: non-null and writable per the caller's contract.
        unsafe { router_out.write(ptr::null_mut()) };
    }
    guard(|| {
        if router_out.is_null() {
            return Err(Error::InvalidArgument("router_out is NULL"));
        }
        // SAFETY: caller contract for every input.
        let (policy, ring, node) = unsafe {
            (
                text(policy_text, "policy is NULL")?,
                bytes(keyring, keyring_len)?,
                text(node, "node is NULL")?,
            )
        };
        let router = Router::new(Policy::parse(policy)?, Keyring::parse(utf8(ring)?)?, node)?;
        let handle = Box::into_raw(Box::new(IlRouter { router }));
        // SAFETY: non-null (checked above) and writable per the caller's contract.
        unsafe { router_out.write(handle) };
        Ok(())
    })
}

/// Route one envelope. Returns `IL_OK` whenever a decision was made, including
/// a rejection: `decision_out` receives the decision's audit line
/// (`verdict=`, `next=`, `reason=` …) and `forward_out` the envelope to send
/// on when the verdict is `forward` (empty otherwise). `arrived_from` is NULL
/// for envelopes handed to the router by a local sender.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_router_route(
    router: *const IlRouter,
    envelope: *const u8,
    envelope_len: usize,
    arrived_from: *const c_char,
    now_ms: u64,
    decision_out: *mut IlBuf,
    forward_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for both outputs.
    unsafe {
        clear(decision_out);
        clear(forward_out);
    }
    guard(|| {
        if router.is_null() {
            return Err(Error::InvalidArgument("router is NULL"));
        }
        // SAFETY: a live handle from il_router_new (Router is Sync), inputs per contract.
        let (handle, env, from) = unsafe {
            (
                &*router,
                bytes(envelope, envelope_len)?,
                opt_text(arrived_from)?,
            )
        };
        let decision = handle.router.route(env, from, now_ms);
        // SAFETY: caller contract for both outputs.
        unsafe {
            give(decision_out, decision.audit_line.into_bytes())?;
            give(forward_out, decision.forwarded.unwrap_or_default())
        }
    })
}

/// Destroy a router. NULL is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_router_free(router: *mut IlRouter) {
    if !router.is_null() {
        // SAFETY: the pointer came from il_router_new and is freed once.
        drop(unsafe { Box::from_raw(router) });
    }
}

/// Strictly decode CBOR and re-encode it: `IL_OK` and identical bytes for
/// canonical input, `IL_E_CBOR` (detail in `il_last_error_id`) otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_cbor_canonical(input: *const u8, len: usize, out: *mut IlBuf) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(out) };
    guard(|| {
        // SAFETY: caller contract for the input.
        let value = cbor::decode(unsafe { bytes(input, len) }?)?;
        // SAFETY: caller contract for the output.
        unsafe { give(out, cbor::encode(&value)?) }
    })
}

/// RFC 8949 diagnostic notation of strictly decoded CBOR.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_cbor_diag(input: *const u8, len: usize, out: *mut IlBuf) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(out) };
    guard(|| {
        // SAFETY: caller contract for the input.
        let value = cbor::decode(unsafe { bytes(input, len) }?)?;
        // SAFETY: caller contract for the output.
        unsafe { give(out, cbor::diag(&value).into_bytes()) }
    })
}

/// Normalize a label: canonical text into `text_out`, CBOR into `cbor_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_label_normalize(
    label: *const c_char,
    text_out: *mut IlBuf,
    cbor_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for both outputs.
    unsafe {
        clear(text_out);
        clear(cbor_out);
    }
    guard(|| {
        // SAFETY: caller contract for the input.
        let parsed = Label::parse(unsafe { text(label, "label is NULL") }?)?;
        let encoded = cbor::encode(&parsed.to_cbor())?;
        // SAFETY: caller contract for both outputs.
        unsafe {
            give(text_out, parsed.to_string().into_bytes())?;
            give(cbor_out, encoded)
        }
    })
}

/// Frame data as CCSDS Space Packets (concatenated), at most `max_data`
/// octets of data per packet, counting from `first_count`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_ccsds_frame(
    apid: u16,
    telecommand: u8,
    first_count: u16,
    max_data: u32,
    data: *const u8,
    len: usize,
    packets_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(packets_out) };
    guard(|| {
        let kind = if telecommand == 0 {
            PacketType::Telemetry
        } else {
            PacketType::Telecommand
        };
        let max = usize::try_from(max_data)
            .map_err(|_| Error::InvalidArgument("max_data is too large"))?;
        // SAFETY: caller contract for the input.
        let framed = ccsds::frame(apid, kind, first_count, unsafe { bytes(data, len) }?, max)?;
        // SAFETY: caller contract for the output.
        unsafe { give(packets_out, framed) }
    })
}

/// Reassemble concatenated Space Packets carrying exactly one message.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_ccsds_deframe(
    packets: *const u8,
    len: usize,
    max_total: u32,
    data_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(data_out) };
    guard(|| {
        let max = usize::try_from(max_total)
            .map_err(|_| Error::InvalidArgument("max_total is too large"))?;
        // SAFETY: caller contract for the input.
        let message = ccsds::deframe(unsafe { bytes(packets, len) }?, max)?;
        // SAFETY: caller contract for the output.
        unsafe { give(data_out, message) }
    })
}

/// Encode one Space Packet from its header fields. `sequence_flags` is the
/// 2-bit field: 0 continuation, 1 first, 2 last, 3 unsegmented.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_ccsds_packet_encode(
    telecommand: u8,
    secondary_header: u8,
    apid: u16,
    sequence_flags: u8,
    sequence_count: u16,
    data: *const u8,
    len: usize,
    packet_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(packet_out) };
    guard(|| {
        let flags = match sequence_flags {
            0 => ccsds::SequenceFlags::Continuation,
            1 => ccsds::SequenceFlags::First,
            2 => ccsds::SequenceFlags::Last,
            3 => ccsds::SequenceFlags::Unsegmented,
            _ => return Err(Error::InvalidArgument("sequence_flags must be 0-3")),
        };
        let packet = ccsds::SpacePacket {
            packet_type: if telecommand == 0 {
                PacketType::Telemetry
            } else {
                PacketType::Telecommand
            },
            secondary_header: secondary_header != 0,
            apid,
            flags,
            sequence_count,
            // SAFETY: caller contract for the input.
            data: unsafe { bytes(data, len) }?.to_vec(),
        };
        // SAFETY: caller contract for the output.
        unsafe { give(packet_out, packet.encode()?) }
    })
}

/// Decode the Space Packet at the start of `bytes`: header fields into the
/// out-parameters, data into `data_out`, packet length into `consumed_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_ccsds_packet_decode(
    bytes_in: *const u8,
    len: usize,
    telecommand_out: *mut u8,
    secondary_header_out: *mut u8,
    apid_out: *mut u16,
    sequence_flags_out: *mut u8,
    sequence_count_out: *mut u16,
    consumed_out: *mut usize,
    data_out: *mut IlBuf,
) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(data_out) };
    guard(|| {
        if telecommand_out.is_null()
            || secondary_header_out.is_null()
            || apid_out.is_null()
            || sequence_flags_out.is_null()
            || sequence_count_out.is_null()
            || consumed_out.is_null()
        {
            return Err(Error::InvalidArgument("an output pointer is NULL"));
        }
        // SAFETY: caller contract for the input.
        let (packet, consumed) = ccsds::SpacePacket::decode(unsafe { bytes(bytes_in, len) }?)?;
        let flags = match packet.flags {
            ccsds::SequenceFlags::Continuation => 0,
            ccsds::SequenceFlags::First => 1,
            ccsds::SequenceFlags::Last => 2,
            ccsds::SequenceFlags::Unsegmented => 3,
        };
        // SAFETY: every pointer was checked non-null above and is writable per the caller's contract.
        unsafe {
            telecommand_out.write(u8::from(packet.packet_type == PacketType::Telecommand));
            secondary_header_out.write(u8::from(packet.secondary_header));
            apid_out.write(packet.apid);
            sequence_flags_out.write(flags);
            sequence_count_out.write(packet.sequence_count);
            consumed_out.write(consumed);
            give(data_out, packet.data)
        }
    })
}

/// SHA-384 of the input (key identifiers are SHA-384 of the raw public key).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn il_sha384(input: *const u8, len: usize, out: *mut IlBuf) -> i32 {
    // SAFETY: caller contract for the output.
    unsafe { clear(out) };
    guard(|| {
        // SAFETY: caller contract for the input and the output.
        unsafe { give(out, crypto::sha384(bytes(input, len)?).to_vec()) }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn take(buf: &mut IlBuf) -> Vec<u8> {
        let v = if buf.ptr.is_null() {
            Vec::new()
        } else {
            // SAFETY: filled by this library just before.
            unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) }.to_vec()
        };
        // SAFETY: a buffer this library filled.
        unsafe { il_buf_free(buf) };
        v
    }

    #[test]
    fn errors_are_reported_and_buffers_reset() {
        let mut out = IlBuf {
            ptr: 7 as *mut u8,
            len: 3,
        };
        // SAFETY: valid pointers; deliberately bad CBOR.
        let rc = unsafe { il_cbor_canonical(b"\x18\x01".as_ptr(), 2, &mut out) };
        assert_eq!(rc, -10);
        assert!(out.ptr.is_null() && out.len == 0, "output reset on failure");
        let mut id = IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        // SAFETY: valid output pointer.
        assert_eq!(unsafe { il_last_error_id(&mut id) }, IL_OK);
        assert_eq!(take(&mut id), b"Cbor/NonCanonicalInteger");
        // SAFETY: NULL inputs are refused, not dereferenced.
        assert_eq!(unsafe { il_cbor_canonical(ptr::null(), 5, &mut out) }, -1);
        // SAFETY: static C string.
        let name = unsafe { CStr::from_ptr(il_error_name(-31)) };
        assert_eq!(name.to_str().unwrap(), "BadSignature");
    }

    #[test]
    fn keygen_seal_open_route() {
        let mut secret = IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let mut public = IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        // SAFETY: valid pointers.
        let rc = unsafe { il_keygen(c"ground-ops".as_ptr(), &mut secret, &mut public) };
        assert_eq!(rc, IL_OK);
        let (secret, public) = (take(&mut secret), take(&mut public));
        let mut env = IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        // SAFETY: valid pointers.
        let rc = unsafe {
            il_seal(
                secret.as_ptr(),
                secret.len(),
                ptr::null(),
                0,
                c"ground-ops".as_ptr(),
                c"conf=low integ=low avail=low".as_ptr(),
                c"text/plain".as_ptr(),
                1_767_225_600_000,
                60_000,
                4,
                b"hi".as_ptr(),
                2,
                &mut env,
            )
        };
        assert_eq!(rc, IL_OK);
        let env = take(&mut env);
        // SAFETY: valid pointers.
        let rc = unsafe { il_verify(public.as_ptr(), public.len(), env.as_ptr(), env.len()) };
        assert_eq!(rc, IL_OK);
        let mut payload = IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        // SAFETY: valid pointers.
        let rc = unsafe {
            il_open(
                ptr::null(),
                0,
                public.as_ptr(),
                public.len(),
                env.as_ptr(),
                env.len(),
                &mut payload,
            )
        };
        assert_eq!(rc, IL_OK);
        assert_eq!(take(&mut payload), b"hi");

        let policy =
            c"policy version=1 name=t\ndomain name=ground-ops conf=low integ=low avail=low\n";
        let mut router: *mut IlRouter = ptr::null_mut();
        // SAFETY: valid pointers.
        let rc = unsafe {
            il_router_new(
                policy.as_ptr(),
                public.as_ptr(),
                public.len(),
                c"ground-ops".as_ptr(),
                &mut router,
            )
        };
        assert_eq!(rc, IL_OK);
        let mut decision = IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let mut forward = IlBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        // SAFETY: live router, valid pointers.
        let rc = unsafe {
            il_router_route(
                router,
                env.as_ptr(),
                env.len(),
                ptr::null(),
                1_767_225_600_500,
                &mut decision,
                &mut forward,
            )
        };
        assert_eq!(rc, IL_OK);
        let line = String::from_utf8(take(&mut decision)).unwrap();
        assert!(line.contains(" verdict=deliver "), "{line}");
        assert!(take(&mut forward).is_empty());
        // SAFETY: from il_router_new, freed once.
        unsafe { il_router_free(router) };
    }
}
