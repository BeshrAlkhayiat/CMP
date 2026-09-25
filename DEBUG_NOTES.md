# CMP Gateway – Debug & Fix Notes

Handoff document. Everything needed to continue is in this file plus the repo state.
Last updated: 2026-09-25 (session where the fix was completed and compiled).

## 1. Original symptom

`gradle runGateway` starts fine, EE sends a **signature-protected** CMP request, gateway
fetches the CA chain from CEMA (`GET /ca/CEMA-User-CA/chain` → CEMA User CA + CEMA Root CA),
then the RA component logs:

```
WARN ...msgvalidation.SignatureProtectionValidator - validating the protection certificate failed
WARN ...msgvalidation.BaseCmpException - error at CMP upstream: validating the protection certificate failed
```

MAC/password-protected flows work; only signature-protected requests fail.

## 2. Root cause (verified, not speculation)

1. For signature-protected requests the gateway self-generates the CertRep upstream
   (`CmpGateway.RestUpstream.protectUpstreamResponse`) and protects it with the **gateway's
   own client certificate** from `ClientAuthCert-CEMA-Admin.p12`.
2. That leaf is `CN=CEMA Admin, OU=CEMA Admins, ...`, issued by **`CN=BoarderZone Dev CA`** —
   a different PKI than the enrollment CA.
3. `GatewayConfig.getUpstreamConfiguration().getInputVerification().getTrustedCertificates()`
   returns the auto-fetched **CEMA User CA / CEMA Root CA** chain as trust anchors.
4. The cmp-ra-component re-validates everything the `UpstreamExchange` callback returns via
   `SignatureProtectionValidator.validate()` → takes extraCerts[0] as protecting cert, checks
   the signature bytes against it, then `TrustCredentialAdapter.validateCertAgainstTrust()`.
   A PKIX path from "CEMA Admin @ BoarderZone Dev CA" to the CEMA anchors can never be built
   → exactly the observed warning. Note: `validateCertAgainstTrust` returns null (= reject!)
   when `getTrustedCertificates()` is null too, so "return null to skip validation" does NOT
   work for the *upstream* direction in this version — worth remembering.
5. The existing `selfGeneratedUpstreamMessage` ThreadLocal workaround in GatewayConfig does
   not cover this code path (validation happens after the callback returns, on a different
   context object instance).

## 3. Fix implemented (COMPLETE, compiles clean)

All changes are in **one file**:
`cmp-gateway/src/main/java/com/siemens/pki/cmpgateway/server/CmpGateway.java` (class `RestUpstream`).

Approach: for signature-protected requests, the self-generated response now **echoes the
request's signer certificate(s)** as its extraCerts (mirroring real CMP server behaviour,
RFC 4210 §5.1.3.1.3) instead of embedding the untrusted gateway admin cert, and the message
is re-signed so the signature actually verifies against the echoed cert.

Pieces:

- `protectUpstreamResponse(...)`:
  - PBM (PasswordBasedMac) → unchanged (mirrors shared secret via `buildReusedCredentialContext`).
  - New branch `isSignatureProtectedRequest(request)` → protector built from
    `buildEchoedExtraCertsInterface(upstreamConfig, request)`; afterwards
    `reSignWithClientKey(protectedResponse, request)`.
  - Unprotected/PBMAC1 → unchanged fallback to configured upstream output credentials.
- `isSignatureProtectedRequest(request)`: true unless protectionAlg is null, passwordBasedMac or id_PBMAC1.
- `buildEchoedExtraCertsInterface(base, request)`: anonymous `CmpMessageInterface` whose
  `getOutputCredentials()` is a `SignatureCredentialContext` returning the request's
  extraCerts as chain (MsgOutputProtector embeds them); its `getInputVerification()` wraps
  the base verification so that `getTrustedCertificates()` returns **exactly the echoed
  signer certs** (trust-without-PKIX for this one cert — it cannot chain to the CA before it
  was issued) and `isLeafCertAcceptable`/`isIntermediateCertAcceptable` return true.
  `getPrivateKey()` delegates to the base keystore key (placeholder; replaced by re-signing).
- `reSignWithClientKey(response, request)`:
  - If the gateway keystore key matches the echoed leaf (`privateKeyMatchesCertificate`),
    the MsgOutputProtector signature is already valid → return unchanged. (This is the case
    for self-signed LCMP-style test clients whose key lives in the same keystore.)
  - Else find the matching private key in the PKCS#12 keystore
    (`findMatchingPrivateKey`: scans key entries, compares chain certs byte-wise via
    `Arrays.equals(cert.getEncoded(), ...)`) and sign
    `new ProtectedPart(header, body).getEncoded(ASN1Encoding.DER)` with
    `AlgorithmHelper.getSignature(AlgorithmHelper.getSigningAlgNameFromKey(key))`.
  - Rebuild: `new PKIMessage(PKIHeader.getInstance(header.toASN1Primitive()), body, protection, extraCerts)`
    — **BC constructor order is (header, body, ASN1BitString protection, CMPCertificate[])**,
    not (…, extraCerts, protection). This bit caused a compile error earlier; fixed.
  - No matching key locally → warn + return unchanged (RA rejects with clear log).
- Helpers: `privateKeyMatchesCertificate` (RSA modulus / EC params compare, fallback
  `verifyRoundTrip`), `pickSignatureAlgorithm`, `protectionAlgorithmName`.
- Imports added: `java.util.Arrays`, `java.util.Collection`, `org.bouncycastle.asn1.DERBitString`,
  `org.bouncycastle.asn1.cmp.PKIHeader`, `org.bouncycastle.asn1.cmp.ProtectedPart`,
  `com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext` (+ X509/List already present).

### Gotchas hit during implementation (do not regress)

- `PKIMessage` ctor param order (see above) — verified with
  `javap -cp "cmp-ra-component/target/CmpRaComponent-4.3.0.jar:cmp-ra-component/target/lib/*" org.bouncycastle.asn1.cmp.PKIMessage`.
- `VerificationContext` has **no** `getSharedSecretName()` in this RA version — don't override it.
- Sources of the RA component internals: `cmp-ra-component/target/CmpRaComponent-4.3.0-sources.jar`
  (read with python zipfile; `unzip` is not installed here). Key classes to consult:
  `SignatureProtectionValidator`, `TrustCredentialAdapter`, `MsgOutputProtector`.
- There was an intermediate broken draft in `reSignWithClientKey` (leftover ternary
  `algorithm == null ? null : response.getHeader(), protection) != null ? ... : response`).
  It is gone; current code is clean.

## 4. Verification status

- [x] Compiles: `javac -nowarn -cp "cmp-ra-component/target/CmpRaComponent-4.3.0.jar:cmp-ra-component/target/lib/*" -d /tmp/out $(find cmp-gateway/src/main/java -name '*.java')` → no errors.
- [ ] Runtime test pending (must run on the Windows box against live CEMA):
      `gradle runGateway`, replay the signature-protected IR from the EE.
      Expected: no more `validating the protection certificate failed`; either
      "upstream response re-signed with the EE key ..." INFO log or silent pass when the
      keystore key equals the echoed signer.
- [ ] If the EE uses a key the gateway does not have locally (real smartcard/EE keypair,
      gateway keystore contains only the CEMA-Admin cert): re-signing is impossible. Then use
      one of the fallbacks in §5.

## 5. Fallback options if echo+resign is not acceptable

a) Configure the EE to use **MAC protection** (RFC 9483 default) — fully supported already
   via `buildReusedCredentialContext` / PBM mirror branch.
b) Make the gateway keystore chain trusted: put the BoarderZone chain into the truststore used
   by `auth.truststore.path` AND merge `getTrustedCertificatesFromTrustStore()` into the
   auto-fetched CA chain in `GatewayConfig.getUpstreamConfiguration().getInputVerification()`
   (currently auto-chain wins exclusively; also remember null ≠ skip in this RA version —
   validateCertAgainstTrust treats null-trust as failure, so keep returning a non-empty list).
c) Extend the `selfGeneratedUpstreamMessage` ThreadLocal idea: have
   `getTrustedCertificates()` return the gateway's own leaf whenever the validating cert
   equals it (requires plumbing the candidate cert into GatewayConfig).

## 6. Repo state / environment notes

- Working tree: `/workspace` (git repo). Modified files per `git status`:
  `.gitignore` (pre-existing change) and
  `cmp-gateway/src/main/java/com/siemens/pki/cmpgateway/server/CmpGateway.java` (this fix) —
  review with `git diff` before committing.
- Sandbox has no gradle/network; javac 17 + the prebuilt RA jars under
  `cmp-ra-component/target/` are the verification tools available here.
- User runs the gateway on Windows: `PS D:\Projects\CMP\cmp-gateway> gradle runGateway`,
  config in `gateway.properties`, CA name `CEMA-User-CA`, REST base `https://localhost:5443/cema/ccm/svc/db.file/rest/v2`,
  gateway listens on port 9000 path /cmp.

## 7. Suggested next actions

1. Run the end-to-end test (§4 unchecked boxes) with the actual signature-protected EE.
2. Check which key the EE signs with; if it's not in `ClientAuthCert-CEMA-Admin.p12`,
   decide between fallbacks (§5) — (b) is the least invasive for production.
3. Consider adding a unit/integration test using the LCMP test client (self-signed cert +
   key in one PKCS#12) to lock in the echo/resign path.
4. Commit with a message like: "Fix upstream validation of self-generated responses to
   signature-protected requests: echo EE signer cert + re-sign".
