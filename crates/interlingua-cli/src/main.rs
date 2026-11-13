//! `il`: the interlingua command line.
//!
//! Each command is a filter in the Unix tradition: data in on stdin, data out
//! on stdout, diagnostics on stderr, and a meaningful exit status.

#![forbid(unsafe_code)]

mod generate;

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use interlingua::audit::{self, AuditChain};
use interlingua::ccsds::{self, PacketType};
use interlingua::envelope::{self, Draft};
use interlingua::{
    Envelope, Error, Keyring, Label, Policy, PublicKeys, Router, SecretKeys, Verdict, cbor, crypto,
    hex, uuid7, vectors,
};

const USAGE: &str = "\
il: secure polyglot message fabric (interlingua)

USAGE
  il keygen <domain> <out-prefix>      write <prefix>.key (mode 0600) and <prefix>.pub
  il seal --key <sender.key> --dst <domain> --label <label>
          [--to <recipient.pub>] [--type <media/type>] [--ttl <seconds>] [--hops <n>] [--now <unix-ms>]
                                       payload on stdin -> envelope on stdout
  il open --keyring <file> [--key <recipient.key>]
                                       envelope on stdin -> verified payload on stdout
  il verify --keyring <file>           envelope on stdin; exit 0 when authentic
  il inspect                           envelope on stdin -> header as attr=value (UNVERIFIED)
  il route --policy <file> --keyring <file> --node <domain>
          [--from <domain>] [--audit <file>] [--out <file>] [--now <unix-ms>]
                                       envelope on stdin -> decision line on stdout;
                                       forwarded envelope to --out; decision appended to --audit
  il audit-verify <file>               verify a hash-chained audit log; prints the chain head
  il cbor diag                         CBOR on stdin -> RFC 8949 diagnostic notation
  il ccsds frame --apid <n> [--tc] [--count <n>] [--max-data <n>]
                                       data on stdin -> CCSDS space packets on stdout
  il ccsds deframe [--max <bytes>]     space packets on stdin -> data on stdout
  il spki <file.pub>                   ML-DSA-87 key as X.509 SubjectPublicKeyInfo DER
  il vectors check <dir>               run the conformance vectors in <dir>
  il vectors generate <dir>            regenerate envelope.rsp and routing.rsp
  il version

LABELS   conf=<n/a|low|moderate|high> integ=<low|moderate|high> avail=<low|moderate|high> [comp=a,b]
EXIT     0 ok · 1 refused (bad signature, rejected, check failed) · 64 usage
         65 bad input data · 66 cannot open input · 70 internal error · 73 cannot create output · 74 I/O error
";

/// BSD sysexits(3) codes plus 1 for "refused".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Refused = 1,
    Usage = 64,
    DataErr = 65,
    NoInput = 66,
    Software = 70,
    CantCreate = 73,
    IoErr = 74,
}

#[derive(Debug)]
struct Failure {
    exit: Exit,
    message: String,
}

impl Failure {
    fn new(exit: Exit, message: impl Into<String>) -> Self {
        Self {
            exit,
            message: message.into(),
        }
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        let exit = match e {
            Error::BadSignature
            | Error::UnknownSigner
            | Error::SignerNotAuthorized
            | Error::Decrypt
            | Error::WrongRecipient
            | Error::KeyRequired => Exit::Refused,
            Error::Crypto(_) => Exit::Software,
            Error::InvalidArgument(_) => Exit::Usage,
            _ => Exit::DataErr,
        };
        Self::new(exit, e.to_string())
    }
}

type Outcome = Result<(), Failure>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            let _ = writeln!(io::stderr(), "il: {}", f.message);
            ExitCode::from(f.exit as u8)
        }
    }
}

/// Parsed `--flag value` options plus positional arguments.
struct Opts {
    flags: Vec<(String, Option<String>)>,
    positional: Vec<String>,
}

impl Opts {
    fn parse(args: &[String], switches: &[&str]) -> Result<Self, Failure> {
        let mut flags = Vec::new();
        let mut positional = Vec::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if switches.contains(&name) {
                    flags.push((name.to_owned(), None));
                } else {
                    let value = iter.next().ok_or_else(|| {
                        Failure::new(Exit::Usage, format!("--{name} needs a value"))
                    })?;
                    flags.push((name.to_owned(), Some(value.clone())));
                }
            } else {
                positional.push(arg.clone());
            }
        }
        Ok(Self { flags, positional })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn need(&self, name: &str) -> Result<&str, Failure> {
        self.get(name)
            .ok_or_else(|| Failure::new(Exit::Usage, format!("--{name} is required\n\n{USAGE}")))
    }

    fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == name)
    }

    fn number<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, Failure> {
        self.get(name).map_or(Ok(default), |v| {
            v.parse()
                .map_err(|_| Failure::new(Exit::Usage, format!("--{name} must be a number")))
        })
    }

    fn check_known(&self, known: &[&str]) -> Outcome {
        match self
            .flags
            .iter()
            .find(|(k, _)| !known.contains(&k.as_str()))
        {
            Some((k, _)) => Err(Failure::new(
                Exit::Usage,
                format!("unknown option --{k}\n\n{USAGE}"),
            )),
            None => Ok(()),
        }
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|e| Failure::new(Exit::NoInput, format!("{path}: {e}")))
}

fn read_text(path: &str) -> Result<String, Failure> {
    String::from_utf8(read_file(path)?)
        .map_err(|_| Failure::new(Exit::DataErr, format!("{path}: not UTF-8 text")))
}

fn stdin_bytes() -> Result<Vec<u8>, Failure> {
    let mut buf = Vec::new();
    io::stdin()
        .lock()
        .take(64 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| Failure::new(Exit::IoErr, format!("stdin: {e}")))?;
    Ok(buf)
}

fn stdout_bytes(data: &[u8]) -> Outcome {
    let mut out = io::stdout().lock();
    out.write_all(data)
        .and_then(|()| out.flush())
        .map_err(|e| Failure::new(Exit::IoErr, format!("stdout: {e}")))
}

fn now_ms(opts: &Opts) -> Result<u64, Failure> {
    if let Some(v) = opts.get("now") {
        return v
            .parse()
            .map_err(|_| Failure::new(Exit::Usage, "--now must be Unix milliseconds"));
    }
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::new(Exit::Software, "system clock is before 1970"))?;
    u64::try_from(since.as_millis())
        .map_err(|_| Failure::new(Exit::Software, "system clock is out of range"))
}

/// Create a file that must not exist yet, with mode 0600 on Unix.
fn create_private(path: &Path, data: &[u8]) -> Outcome {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut f| f.write_all(data).and_then(|()| f.sync_all()))
        .map_err(|e| Failure::new(Exit::CantCreate, format!("{}: {e}", path.display())))
}

fn run(args: &[String]) -> Outcome {
    let Some((command, rest)) = args.split_first() else {
        return Err(Failure::new(Exit::Usage, USAGE));
    };
    match command.as_str() {
        "keygen" => keygen(rest),
        "seal" => seal(rest),
        "open" => open(rest),
        "verify" => verify(rest),
        "inspect" => inspect(rest),
        "route" => route(rest),
        "audit-verify" => audit_verify(rest),
        "cbor" => cbor_command(rest),
        "ccsds" => ccsds_command(rest),
        "spki" => spki(rest),
        "vectors" => vectors_command(rest),
        "version" | "--version" => {
            let backend = if interlingua::fips_build() {
                "AWS-LC FIPS module"
            } else {
                "AWS-LC"
            };
            stdout_bytes(
                format!(
                    "il {} (wire format {}, suite IL1-CNSA2, {backend})\n",
                    interlingua::VERSION,
                    interlingua::FORMAT_VERSION
                )
                .as_bytes(),
            )
        }
        "help" | "--help" | "-h" => stdout_bytes(USAGE.as_bytes()),
        other => Err(Failure::new(
            Exit::Usage,
            format!("unknown command `{other}`\n\n{USAGE}"),
        )),
    }
}

fn keygen(args: &[String]) -> Outcome {
    let opts = Opts::parse(args, &[])?;
    opts.check_known(&[])?;
    let [domain, prefix] = opts.positional.as_slice() else {
        return Err(Failure::new(
            Exit::Usage,
            "usage: il keygen <domain> <out-prefix>",
        ));
    };
    let keys = SecretKeys::generate(domain)?;
    let secret = keys.to_text()?;
    let key_path = PathBuf::from(format!("{prefix}.key"));
    let pub_path = PathBuf::from(format!("{prefix}.pub"));
    create_private(&key_path, secret.as_bytes())?;
    create_private(&pub_path, keys.public().to_text().as_bytes())?;
    let note = format!(
        "{}: secret keys (0600) · {}: public keys\nsigning key sha384:{}\n",
        key_path.display(),
        pub_path.display(),
        hex::encode(&keys.signing.key_id())
    );
    let _ = io::stderr().write_all(note.as_bytes());
    Ok(())
}

fn seal(args: &[String]) -> Outcome {
    let opts = Opts::parse(args, &[])?;
    opts.check_known(&["key", "dst", "label", "to", "type", "ttl", "hops", "now"])?;
    let sender = SecretKeys::parse(&read_text(opts.need("key")?)?)?;
    let dst = opts.need("dst")?;
    let recipient = opts
        .get("to")
        .map(|p| read_text(p).and_then(|t| PublicKeys::parse(&t).map_err(Failure::from)))
        .transpose()?;
    if let Some(r) = &recipient
        && r.domain != dst
    {
        return Err(Failure::new(
            Exit::Usage,
            format!("--to holds keys for {}, not --dst {dst}", r.domain),
        ));
    }
    let payload = stdin_bytes()?;
    let ttl_s: u64 = opts.number("ttl", 3600)?;
    let draft = Draft {
        src: &sender.domain,
        dst,
        label: Label::parse(opts.need("label")?)?,
        content_type: opts.get("type").unwrap_or("application/octet-stream"),
        ttl_ms: ttl_s.saturating_mul(1000),
        max_hops: opts.number("hops", 8)?,
        payload: &payload,
    };
    let ek = recipient.as_ref().map(|r| r.encapsulation_key.as_slice());
    let wire = envelope::seal_and_sign(&draft, &sender.signing, ek, now_ms(&opts)?)?.encode()?;
    stdout_bytes(&wire)
}

fn load_keyring(path: &str) -> Result<Keyring, Failure> {
    Ok(Keyring::parse(&read_text(path)?)?)
}

fn open(args: &[String]) -> Outcome {
    let opts = Opts::parse(args, &[])?;
    opts.check_known(&["keyring", "key"])?;
    let ring = load_keyring(opts.need("keyring")?)?;
    let recipient = opts
        .get("key")
        .map(|p| read_text(p).and_then(|t| SecretKeys::parse(&t).map_err(Failure::from)))
        .transpose()?;
    let env = Envelope::decode(&stdin_bytes()?)?;
    let payload = env.verify_and_open(&ring, recipient.as_ref().map(|k| &k.decapsulation))?;
    stdout_bytes(&payload)
}

fn verify(args: &[String]) -> Outcome {
    let opts = Opts::parse(args, &[])?;
    opts.check_known(&["keyring"])?;
    let ring = load_keyring(opts.need("keyring")?)?;
    let env = Envelope::decode(&stdin_bytes()?)?;
    let signer = env.verify(&ring)?;
    stdout_bytes(
        format!(
            "authentic: signed by {} (sha384:{})\n",
            signer.domain,
            hex::encode(&env.header.signer)
        )
        .as_bytes(),
    )
}

fn inspect(args: &[String]) -> Outcome {
    Opts::parse(args, &[])?.check_known(&[])?;
    let env = Envelope::decode(&stdin_bytes()?)?;
    let h = &env.header;
    let text = format!(
        "# UNVERIFIED: decoded only; run `il verify` before trusting any field\n\
         id         {}\nsrc        {}\ndst        {}\nlabel      {}\ncreated    {}\nexpires    {}\n\
         hops       {} of {}\ntype       {}\nsealed     {}\nsigner     sha384:{}\nbytes      payload {}, signature {}\n",
        uuid7::format(&h.id),
        h.src,
        h.dst,
        h.label,
        h.created_ms,
        h.expires_ms,
        env.hops,
        h.max_hops,
        h.content_type,
        if h.sealed {
            "yes (ML-KEM-1024 + AES-256-GCM)"
        } else {
            "no"
        },
        hex::encode(&h.signer),
        env.payload.len(),
        env.signature.len(),
    );
    stdout_bytes(text.as_bytes())
}

fn route(args: &[String]) -> Outcome {
    let opts = Opts::parse(args, &[])?;
    opts.check_known(&["policy", "keyring", "node", "from", "audit", "out", "now"])?;
    let policy = Policy::parse(&read_text(opts.need("policy")?)?)?;
    let ring = load_keyring(opts.need("keyring")?)?;
    let router = Router::new(policy, ring, opts.need("node")?)?;
    let audit_path = opts.get("audit");
    if let Some(path) = audit_path
        && let Ok(existing) = fs::read_to_string(path)
    {
        let chain = audit::verify_chain(&existing).map_err(|e| {
            Failure::new(
                Exit::DataErr,
                format!("{path}: refusing to extend a broken audit chain: {e}"),
            )
        })?;
        router.resume_audit(chain.seq(), chain.head());
    }
    let decision = router.route(&stdin_bytes()?, opts.get("from"), now_ms(&opts)?);
    if let Some(path) = audit_path {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Failure::new(Exit::CantCreate, format!("{path}: {e}")))?;
        writeln!(file, "{}", decision.audit_line)
            .map_err(|e| Failure::new(Exit::IoErr, format!("{path}: {e}")))?;
    }
    if let (Some(path), Some(bytes)) = (opts.get("out"), &decision.forwarded) {
        fs::write(path, bytes)
            .map_err(|e| Failure::new(Exit::CantCreate, format!("{path}: {e}")))?;
    }
    stdout_bytes(format!("{}\n", vectors::verdict_text(&decision.verdict)).as_bytes())?;
    match decision.verdict {
        Verdict::Reject(_) => Err(Failure::new(
            Exit::Refused,
            "message rejected (see the decision above)",
        )),
        _ => Ok(()),
    }
}

fn audit_verify(args: &[String]) -> Outcome {
    let opts = Opts::parse(args, &[])?;
    opts.check_known(&[])?;
    let [path] = opts.positional.as_slice() else {
        return Err(Failure::new(Exit::Usage, "usage: il audit-verify <file>"));
    };
    let chain: AuditChain = audit::verify_chain(&read_text(path)?)
        .map_err(|e| Failure::new(Exit::Refused, e.to_string()))?;
    stdout_bytes(
        format!(
            "chain intact: {} record(s), head sha384:{}\n",
            chain.seq(),
            hex::encode(&chain.head())
        )
        .as_bytes(),
    )
}

fn cbor_command(args: &[String]) -> Outcome {
    match args.first().map(String::as_str) {
        Some("diag") => {
            let value = cbor::decode(&stdin_bytes()?).map_err(Error::from)?;
            stdout_bytes(format!("{}\n", cbor::diag(&value)).as_bytes())
        }
        _ => Err(Failure::new(
            Exit::Usage,
            "usage: il cbor diag < input.cbor",
        )),
    }
}

fn ccsds_command(args: &[String]) -> Outcome {
    let Some((sub, rest)) = args.split_first() else {
        return Err(Failure::new(Exit::Usage, "usage: il ccsds frame|deframe …"));
    };
    let opts = Opts::parse(rest, &["tc"])?;
    match sub.as_str() {
        "frame" => {
            opts.check_known(&["apid", "tc", "count", "max-data"])?;
            let apid: u16 = opts
                .need("apid")?
                .parse()
                .map_err(|_| Failure::new(Exit::Usage, "--apid must be 0-2046"))?;
            let kind = if opts.has("tc") {
                PacketType::Telecommand
            } else {
                PacketType::Telemetry
            };
            let framed = ccsds::frame(
                apid,
                kind,
                opts.number("count", 0)?,
                &stdin_bytes()?,
                opts.number("max-data", ccsds::MAX_DATA_LEN)?,
            )?;
            stdout_bytes(&framed)
        }
        "deframe" => {
            opts.check_known(&["max"])?;
            let data = ccsds::deframe(&stdin_bytes()?, opts.number("max", 16 * 1024 * 1024)?)?;
            stdout_bytes(&data)
        }
        _ => Err(Failure::new(Exit::Usage, "usage: il ccsds frame|deframe …")),
    }
}

fn spki(args: &[String]) -> Outcome {
    let [path] = args else {
        return Err(Failure::new(Exit::Usage, "usage: il spki <file.pub>"));
    };
    let keys = PublicKeys::parse(&read_text(path)?)?;
    stdout_bytes(&crypto::mldsa87_spki(&keys.verifying_key)?)
}

fn vectors_command(args: &[String]) -> Outcome {
    let (Some(sub), Some(dir)) = (args.first(), args.get(1)) else {
        return Err(Failure::new(
            Exit::Usage,
            "usage: il vectors check|generate <dir>",
        ));
    };
    let dir = Path::new(dir);
    match sub.as_str() {
        "check" => {
            let file = |name: &str| read_text(&dir.join(name).to_string_lossy());
            let mut report = vectors::Report::default();
            let mut ran = Vec::new();
            for (name, result) in [
                (
                    "cbor.rsp",
                    file("cbor.rsp").and_then(|t| vectors::check_cbor(&t).map_err(Failure::from)),
                ),
                (
                    "label.rsp",
                    file("label.rsp").and_then(|t| vectors::check_label(&t).map_err(Failure::from)),
                ),
                (
                    "ccsds.rsp",
                    file("ccsds.rsp").and_then(|t| vectors::check_ccsds(&t).map_err(Failure::from)),
                ),
                (
                    "envelope.rsp",
                    file("envelope.rsp").and_then(|t| {
                        vectors::check_envelope(
                            &t,
                            &file("keyring.pub")?,
                            &file("test-secrets.txt")?,
                        )
                        .map_err(Failure::from)
                    }),
                ),
                (
                    "routing.rsp",
                    file("routing.rsp").and_then(|t| {
                        vectors::check_routing(
                            &t,
                            &file("routing-policy.ndb")?,
                            &file("keyring.pub")?,
                        )
                        .map_err(Failure::from)
                    }),
                ),
            ] {
                let part = result?;
                ran.push(format!(
                    "{name}: {} passed, {} failed",
                    part.passed,
                    part.failures.len()
                ));
                report.merge(part);
            }
            let mut text = ran.join("\n");
            for f in &report.failures {
                text.push_str("\nFAIL ");
                text.push_str(f);
            }
            text.push('\n');
            stdout_bytes(text.as_bytes())?;
            if report.is_ok() {
                Ok(())
            } else {
                Err(Failure::new(
                    Exit::Refused,
                    format!("{} conformance check(s) failed", report.failures.len()),
                ))
            }
        }
        "generate" => generate::run(dir),
        _ => Err(Failure::new(
            Exit::Usage,
            "usage: il vectors check|generate <dir>",
        )),
    }
}
