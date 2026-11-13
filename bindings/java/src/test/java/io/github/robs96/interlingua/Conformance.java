package io.github.robs96.interlingua;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.KEM;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java conformance runner: the shared vectors through the FFM binding, then
 * independent checks with the JDK's own ML-DSA (JEP 497), ML-KEM (JEP 496),
 * HKDF (JEP 510) and AES-GCM.
 *
 * <pre>java --enable-native-access=ALL-UNNAMED -cp out io.github.robs96.interlingua.Conformance &lt;lib&gt; &lt;vectors-dir&gt;</pre>
 */
public final class Conformance {
    private static final HexFormat HEX = HexFormat.of();
    private static int passed;
    private static int failed;

    /** DER prefixes of SubjectPublicKeyInfo for ML-DSA-87 (OID 2.16.840.1.101.3.4.3.19) and ML-KEM-1024 (2.16.840.1.101.3.4.4.3). */
    private static final byte[] MLDSA87_SPKI = HEX.parseHex("30820a32300b0609608648016503040313038" + "20a2100");
    private static final byte[] MLKEM1024_SPKI = HEX.parseHex("30820632300b060960864801650304040303820621" + "00");

    private Conformance() {
    }

    private interface Body<T> {
        T run() throws Exception;
    }

    record Rec(String section, Map<String, String> fields) {
        String get(String key) {
            return fields.getOrDefault(key, "");
        }

        boolean has(String key) {
            return fields.containsKey(key);
        }
    }

    record Keys(byte[] pk, byte[] ek) {
    }

    static void check(boolean ok, String what) {
        if (ok) {
            passed++;
        } else {
            failed++;
            System.err.println("FAIL " + what);
        }
    }

    static <T> T attempt(Body<T> body) {
        try {
            return body.run();
        } catch (Exception e) {
            return null;
        }
    }

    static String errorId(Body<?> body) {
        try {
            body.run();
            return null;
        } catch (InterlinguaException e) {
            return e.id();
        } catch (Exception e) {
            return e.toString();
        }
    }

    static List<Rec> parse(Path file) throws IOException {
        List<Rec> out = new ArrayList<>();
        String section = "";
        Map<String, String> cur = new LinkedHashMap<>();
        for (String raw : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String line = raw.strip();
            if (line.startsWith("#")) {
                continue;
            }
            if (line.isEmpty() || (line.startsWith("[") && line.endsWith("]"))) {
                if (!cur.isEmpty()) {
                    out.add(new Rec(section, cur));
                    cur = new LinkedHashMap<>();
                }
                if (!line.isEmpty()) {
                    section = line.substring(1, line.length() - 1).strip();
                }
                continue;
            }
            int eq = line.indexOf('=');
            cur.put(line.substring(0, eq).strip(), line.substring(eq + 1).strip());
        }
        if (!cur.isEmpty()) {
            out.add(new Rec(section, cur));
        }
        return out;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static byte[] secretFor(String secrets, String domain) {
        String magic = "interlingua-secret-key v1\n";
        for (String chunk : secrets.split(magic)) {
            if (chunk.startsWith("domain " + domain + "\n")) {
                return (magic + chunk).getBytes(StandardCharsets.UTF_8);
            }
        }
        throw new IllegalStateException("no test key for " + domain);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: Conformance <native-library> <vectors-dir>");
            System.exit(64);
        }
        Interlingua il = Interlingua.load(Path.of(args[0]));
        Path dir = Path.of(args[1]);

        for (Rec r : parse(dir.resolve("cbor.rsp"))) {
            byte[] in = HEX.parseHex(r.get("cbor"));
            if (r.get("expect").equals("accept")) {
                check(Arrays.equals(attempt(() -> il.cborCanonical(in)), in), "cbor " + r.get("cbor"));
                if (r.has("diag")) {
                    check(r.get("diag").equals(attempt(() -> il.cborDiag(in))), "cbor diag " + r.get("diag"));
                }
            } else {
                check(r.get("error").equals(errorId(() -> il.cborCanonical(in))), "cbor reject " + r.get("cbor"));
            }
        }

        for (Rec r : parse(dir.resolve("label.rsp"))) {
            if (r.get("expect").equals("accept")) {
                byte[][] got = attempt(() -> il.normalizeLabel(r.get("text")));
                check(got != null && new String(got[0], StandardCharsets.UTF_8).equals(r.get("canonical"))
                        && Arrays.equals(got[1], HEX.parseHex(r.get("cbor"))), "label " + r.get("text"));
            } else {
                check(r.get("error").equals(errorId(() -> il.normalizeLabel(r.get("text")))), "label reject " + r.get("text"));
            }
        }

        Map<String, Integer> flags = Map.of("continuation", 0, "first", 1, "last", 2, "unsegmented", 3);
        for (Rec r : parse(dir.resolve("ccsds.rsp"))) {
            byte[] wire = HEX.parseHex(r.get("packet"));
            if (r.get("expect").equals("accept")) {
                SpacePacket want = new SpacePacket(r.get("type").equals("tc"), r.get("sec").equals("1"),
                        Integer.parseInt(r.get("apid")), flags.get(r.get("flags")), Integer.parseInt(r.get("count")),
                        HEX.parseHex(r.get("data")), 0);
                SpacePacket got = attempt(() -> il.decodePacket(wire));
                check(got != null && got.telecommand() == want.telecommand() && got.secondaryHeader() == want.secondaryHeader()
                        && got.apid() == want.apid() && got.sequenceFlags() == want.sequenceFlags()
                        && got.sequenceCount() == want.sequenceCount() && Arrays.equals(got.data(), want.data())
                        && got.consumed() == wire.length, "ccsds decode " + r.get("packet"));
                check(Arrays.equals(attempt(() -> il.encodePacket(want)), wire), "ccsds encode " + r.get("packet"));
            } else {
                check(r.get("error").equals(errorId(() -> il.decodePacket(wire))), "ccsds reject " + r.get("packet"));
            }
        }

        byte[] ring = Files.readAllBytes(dir.resolve("keyring.pub"));
        String secrets = Files.readString(dir.resolve("test-secrets.txt"), StandardCharsets.UTF_8);
        for (Rec r : parse(dir.resolve("envelope.rsp"))) {
            byte[] key = r.has("recipient") ? secretFor(secrets, r.get("recipient")) : null;
            byte[] env = HEX.parseHex(r.get("envelope"));
            if (r.get("expect").equals("valid")) {
                check(Arrays.equals(attempt(() -> il.open(key, ring, env)), HEX.parseHex(r.get("payload"))), "envelope " + r.get("name"));
            } else {
                String want = r.get("expect").substring("error:".length());
                check(want.equals(errorId(() -> il.open(key, ring, env))), "envelope " + r.get("name"));
            }
        }

        String policy = Files.readString(dir.resolve("routing-policy.ndb"), StandardCharsets.UTF_8);
        Map<String, Router> routers = new HashMap<>();
        String section = null;
        byte[] forwarded = new byte[0];
        for (Rec r : parse(dir.resolve("routing.rsp"))) {
            if (!r.section().equals(section)) {
                routers.values().forEach(Router::close);
                routers.clear();
                forwarded = new byte[0];
                section = r.section();
            }
            Router router = routers.computeIfAbsent(r.get("node"), n -> il.router(policy, ring, n));
            byte[] env = r.get("envelope").equals("forwarded") ? forwarded : HEX.parseHex(r.get("envelope"));
            String from = r.get("from").equals("-") ? null : r.get("from");
            Decision d = router.route(env, from, Long.parseLong(r.get("now")));
            String got = switch (d.verdict()) {
                case "forward" -> "forward:" + d.nextHop();
                case "reject" -> "reject:" + d.reason();
                default -> d.verdict();
            };
            check(got.equals(r.get("expect")), "routing [" + r.section() + "] " + r.get("name") + ": wanted "
                    + r.get("expect") + ", got " + got);
            forwarded = d.forward();
        }
        routers.values().forEach(Router::close);
        int shared = passed;

        // ---- independent checks with the JDK's own cryptography ----
        Map<String, Keys> keys = new HashMap<>();
        String domain = null;
        byte[] pk = null;
        for (String line : Files.readAllLines(dir.resolve("keyring.pub"), StandardCharsets.UTF_8)) {
            String[] parts = line.strip().split(" ", 2);
            if (parts.length != 2) {
                continue;
            }
            switch (parts[0]) {
                case "domain" -> domain = parts[1];
                case "mldsa87-pk" -> pk = HEX.parseHex(parts[1]);
                case "mlkem1024-ek" -> keys.put(domain, new Keys(pk, HEX.parseHex(parts[1])));
                default -> {
                }
            }
        }
        KeyFactory dsaKeys = KeyFactory.getInstance("ML-DSA");
        KeyFactory kemKeys = KeyFactory.getInstance("ML-KEM");
        for (Map.Entry<String, Keys> e : keys.entrySet()) {
            PublicKey ek = kemKeys.generatePublic(new X509EncodedKeySpec(concat(MLKEM1024_SPKI, e.getValue().ek())));
            KEM.Encapsulated enc = KEM.getInstance("ML-KEM").newEncapsulator(ek).encapsulate();
            check(enc.encapsulation().length == 1568 && enc.key().getEncoded().length == 32,
                    "JDK ML-KEM-1024 encapsulates to " + e.getKey());
        }
        for (Rec r : parse(dir.resolve("envelope.rsp"))) {
            if (!r.get("expect").equals("valid")) {
                continue;
            }
            PublicKey signer = dsaKeys.generatePublic(new X509EncodedKeySpec(concat(MLDSA87_SPKI, keys.get(r.get("signer")).pk())));
            Signature verifier = Signature.getInstance("ML-DSA");
            verifier.initVerify(signer);
            verifier.update(HEX.parseHex(r.get("signed")));
            check(verifier.verify(HEX.parseHex(r.get("signature"))), "JDK ML-DSA-87 verifies " + r.get("name"));

            if (r.has("kem-ss")) {
                byte[] aad = HEX.parseHex(r.get("aead-aad"));
                int at = 2 + 11; // array(2), text(11) "IL1-Encrypt"
                int offset = (aad[at] & 0xff) == 0x58 ? at + 2 : at + 3;
                int length = (aad[at] & 0xff) == 0x58 ? aad[at + 1] & 0xff : ((aad[at + 1] & 0xff) << 8) | (aad[at + 2] & 0xff);
                byte[] protectedHeader = Arrays.copyOfRange(aad, offset, offset + length);
                var sha384 = java.security.MessageDigest.getInstance("SHA-384");
                byte[] salt = sha384.digest(protectedHeader);
                byte[] info = concat("IL1-Seal-AES256GCM".getBytes(StandardCharsets.US_ASCII),
                        sha384.digest(keys.get(r.get("recipient")).ek()));
                byte[] okm = KDF.getInstance("HKDF-SHA384").deriveData(
                        HKDFParameterSpec.ofExtract().addIKM(HEX.parseHex(r.get("kem-ss"))).addSalt(salt).thenExpand(info, 44));
                check(HEX.formatHex(okm).equals(r.get("aead-key") + r.get("aead-nonce")), "JDK HKDF-SHA-384 matches the Rust derivation");
                Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
                gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Arrays.copyOf(okm, 32), "AES"),
                        new GCMParameterSpec(128, Arrays.copyOfRange(okm, 32, 44)));
                gcm.updateAAD(aad);
                check(Arrays.equals(gcm.doFinal(HEX.parseHex(r.get("aead-ct"))), HEX.parseHex(r.get("payload"))),
                        "JDK AES-256-GCM opens the Rust-sealed payload");
            }
        }

        System.out.printf("Java binding (%s): %d shared-vector checks, %d JDK checks, %d failed%n",
                il.version(), shared, passed - shared, failed);
        System.exit(failed == 0 ? 0 : 1);
    }
}
