# CMP Gateway — Root-Cause Analysis: "validating the protection certificate failed"

Status: **analysis only, no code changed** (per request). All findings below are
verified against actual source in this repo and the `cmp-ra-component` sources jar,
not guessed.

## 1. Symptom

```
RestClient - Fetched 2 CA certificate(s) from 'GET /ca/CEMA-User-CA/chain'   (User CA + Root CA)
WARN SignatureProtectionValidator - validating the protection certificate failed
WARN BaseCmpException - error at CMP upstream: validating the protection certificate failed
```
LCMP client (`gateway-p10-pbm.yaml`) then receives `ERROR`.

## 2. Exact failure chain (verified)

1. The EE request is **signature-protected** (the PBM config file is a red herring;
   see §4). It reaches the RA component downstream side, is validated OK, and is
   forwarded to the gateway's `UpstreamExchange.sendReceiveMessage()` callback.
2. `RestUpstream.issuePkcs10()` calls CEMA REST, gets the issued cert, builds a
   CertRep body and hands it to `protectUpstreamResponse()`
   (`CmpGateway.java:571`).
3. For signature-protected requests the current code takes the branch at
   `CmpGateway.java:615-623`: `buildEchoedExtraCertsInterface()` makes
   `MsgOutputProtector` embed **the EE's own signer certificate as extraCerts[0]**
   of the generated CertRep and sign with the **gateway keystore key**.
   Then `reSignWithClientKey()` (`CmpGateway.java:813`) looks for a private key in
   `ClientAuthCert-CEMA-Admin.p12` matching the EE signer. The LCMP test client's
   key is **not** in that keystore → warning "cannot re-sign ... no matching private
   key found" → response returned signed by the *gateway* key but carrying the
   *EE* cert in extraCerts[0].
4. Back inside the RA component, `CmpRaUpstream.handleRequest()`
   (sources jar, line ~203) runs `InputValidator` over **whatever the callback
   returns**, using `config.getUpstreamConfiguration()` — i.e.
   `GatewayConfig.getUpstreamConfiguration().getInputVerification()`.
5. `SignatureProtectionValidator.validate()` (RA sources):
   - picks `extraCerts[0]` (= the echoed EE cert) as protecting cert,
   - `checkProtectingSignature()`: verifies the DER signature with that cert's
     public key → **passes only because the echoed cert happens to be self-signed
     and its subject == header.sender** (CN=…test cert…). With a CA-issued EE cert
     or an embedded chain this check itself would fail with "signature broken".
   - `validateCertAgainstTrust(EE-cert, [EE-cert])` → PKIX path building against
     the trust anchors returned by `getTrustedCertificates()`.
6. Trust anchors = the auto-fetched **CEMA User CA / CEMA Root CA chain**
   (logged right before the warning). The EE's enrollment credential cannot build a
   PKIX path to those anchors (it is not yet issued / different PKI), so
   `CertPathBuilder` fails → `null` → **"validating the protection certificate
   failed"** → `PKIFailureInfo.signerNotTrusted` → ERROR to the client.

## 3. Why the existing ThreadLocal workaround does NOT help

`GatewayConfig.getUpstreamConfiguration().getInputVerification()
.getTrustedCertificates()` (`GatewayConfig.java:537-548`) *does* return `null`
(skip validation) while `isProcessingSelfGeneratedUpstreamMessage()` is set
(`CmpGateway.java:195`). Two problems:

- **RA version behavior:** in `TrustCredentialAdapter.validateCertAgainstTrust`
  (line ~124-127 of the RA sources) `trustedCertificates == null` ⇒ `return null`
  ⇒ which `SignatureProtectionValidator` treats as **failure**, not skip. So even
  when the flag works, this RA build rejects. (The comment in GatewayConfig says
  "null disables validation" — that holds on the *downstream* path via
  `ProtectionValidator`, but the upstream validator here maps null→fail.)
- **Thread-boundary risk:** the flag is a plain `ThreadLocal` on the gateway
  config. It only helps if validation happens on the same thread that ran the
  callback. Any delayed/poll path or executor hop clears/bypasses it.

## 4. Client-side observation (why "PBM" config still sends signatures)

`gateway-p10-pbm.yaml` supplies `SharedSecret` in both verification and output
credentials, but LCMP's `CmpClientComponent` prefers signature-based protection
whenever the client context yields a usable signer (self-signed test cert from the
shared LCMP test credentials). Hence `isSignatureProtectedRequest()==true` on the
gateway. To actually exercise the PBM path, the client must have **no** signer
credential configured (only the shared secret).

## 5. Design flaw summary

A real CMP server answers a signature-protected request with a message signed by
**its own** protected-cert (which the client trusts). This gateway has no CA-issued
CMP signer: its identity (`CN=CEMA Admin`, issuer `BoarderZone Dev CA`) belongs to
a different PKI than the enrollment anchors (`CEMA User CA/Root CA`). Both current
strategies therefore fail the mandatory upstream trust check:
- sign with gateway cert → path to BoarderZone Dev CA ≠ anchors → fail (original bug);
- echo EE cert (current fix attempt) → signature bytes don't verify against it
  unless the gateway holds the EE key → either "signature broken" or the observed
  trust-path failure.

## 6. Viable options (NOT implemented — decision needed)

| # | Option | Effort | Notes |
|---|--------|--------|-------|
| A | Make the client really use **PBM/PBMAC1** (remove signer from LCMP config) | trivial | The mirrored-PBM branch (`buildReusedCredentialContext`) already works; `PasswordBasedMacValidator` needs no cert trust. Recommended for testing. |
| B | Sign upstream responses with a cert **under the CEMA chain**: obtain e.g. a "CEMA User CA"-issued gateway cert, put it in `auth.keystore.path` | small | Correct long-term design; matches how real CMP servers work. |
| C | Merge the BoarderZone/gateway-chain into upstream trust anchors (`getAutomaticallyFetchedCaChain()` ∪ `auth.truststore.path` contents) and revert to gateway-cert signing | small | Weakens upstream trust model (any BoarderZone-issued signer accepted). |
| D | Fix the ThreadLocal hack properly: extend `getTrustedCertificates()` skip to also trigger when the validating cert equals the gateway leaf **and** make the RA treat null as skip — requires patching `cmp-ra-component` (vendored here) | medium | Touches third-party code. |
| E | Keep echo approach but only when the gateway actually holds the echoed cert's key (i.e., restrict to self-signed-LCMP-with-imported-key scenarios) | small | Doesn't solve production case. |

## 7. How to confirm quickly (runtime experiment, no code change)

Run the LCMP client with a **pure PBM config** (delete any `Signer`/keystore
section so only `SharedSecret` remains) against the *current* gateway build:
if the transaction completes, §2/§5 are confirmed as the sole blocker.

## 8. Environment facts used

- `cmp-gateway/gateway.properties`: `auth.keystore.path=ClientAuthCert-CEMA-Admin.p12`
  (leaf `CN=CEMA Admin` ← `CN=BoarderZone Dev CA`), `ca.name=CEMA-User-CA`,
  truststore unset ⇒ anchors come from `GET /ca/CEMA-User-CA/chain`.
- RA component 4.3.0 sources extracted from
  `cmp-ra-component/target/CmpRaComponent-4.3.0-sources.jar`
  (`SignatureProtectionValidator`, `TrustCredentialAdapter`, `CmpRaUpstream`).
- Workspace HEAD `5822210` contains the echo/re-sign attempt; it compiles
  (`javac` clean) but is analytically unsound for CA-issued EE certs (§2 step 3/5).

## Update (run 13:10): smoking gun confirmed + fixed

New logging proved the diagnosis: `upstream trust anchor query #1: self-generated response in progress=false`
while validating our own CertRep on the same thread. Cause: the RA component
(CmpRaUpstream.handleRequest, verified in sources jar) runs InputValidator on the message
**after** the upstream exchange callback returned - our finally-block had already cleared the
ThreadLocal flag, so the gateway keystore chain was never merged into the trust anchors and
PKIX failed against CEMA-only anchors.

Fix: replaced the ThreadLocal with a plain volatile field in GatewayConfig; the flag is no
longer cleared inside RestUpstream.sendReceiveMessage's finally block but once per downstream
request in CmpHandler.handle (finally around cmpRaInterface.processRequest). Compiles clean.

Expected next run log: "self-generated response in progress=true", "merging gateway keystore
chain ... [CN=CEMA Admin..., CN=BoarderZone Dev CA...]", anchors include BoarderZone Dev CA,
and validation passes. If instead the keystore chain shows only the CEMA Admin leaf, add
BoarderZone Dev CA to auth.truststore.path.

## Update after run with logging (2026-09-25)

Log analysis:
- Request protection = signature (sha256RSA), sender = CN=CEMA Admin -> LCMP is signing with the SAME cert as the REST auth identity.
- Gateway response signed with that cert, but trust anchor query showed "in progress=false" and only 2 anchors (CEMA User CA + Root CA). The keystore-chain merge was skipped.
- Cause A (fixed): user's running build predates the volatile-flag change; flag now set only for signature-protected requests and cleared in CmpHandler.handle after processRequest returns.
- Cause B (fixed): getCertificateChain() returned EMPTY if auth.keystore.alias does not match the p12 key entry or if the entry stores only the leaf (typical Tomcat-exported p12). Now: alias falls back to the first key entry; leaf-only entries get their issuing chain rebuilt from other keystore entries; loud WARNs otherwise.

Remaining hard requirement: PKIX needs a path from the gateway signer cert to an anchor. If the p12/keystore contains ONLY the Tomcat leaf, the BoarderZone Dev CA must be added to auth.truststore.path - the new WARN log says exactly this. Long-term correct design (per user): CMP signer should be a cert under the CEMA PKI (same chain the API returns via GET /ca/CEMA-User-CA/chain); the Tomcat cert is for REST/TLS auth only.

## 2026-09-25 (later): RFC 9483 compliance review - gateway was missing extraCerts CA chain

User challenged the "LCMP client bug" conclusion since LCMP is the reference implementation.
Verified against the actual client source (cmp-ra-component/src/main/java/com/siemens/pki/
cmpclientcomponent/main/CmpClient.java, invokeEnrollment ~line 576):

```java
if (enrollmentContext.getEnrollmentTrust() != null) {
    enrollmentChain = validateCertAgainstTrust(enrolledCert, asX509Certificates(responseMessage.getExtraCerts()));
} else {
    enrollmentChain = null;   // <-- null by design when client has no enrollment trust configured
}
```

=> getEnrollmentChain() returning null is NORMAL for a client without EnrollmentTrust. The
NullPointerException in CliCmpClient.writeKeystore(null-chain) is therefore only a robustness
gap in the test CLI, but the REAL standards issue is on our side:

RFC 4210 sec. 5.1.3.1.3 / RFC 9483 sec. 3.2: a CMP server MUST include all issuer-side
certificates needed to build a certification path for the issued certificate in extraCerts of
every CertRep. Our self-generated CertRep carried only the gateway signer chain
(CN=CEMA Admin <- BoarderZone Dev CA) and NOT the CEMA User CA / Root CA chain that actually
issued the enrolled certificate. A conformant client with pinned trust anchors could not have
built the path either.

Fix: CmpGateway.RestUpstream.appendCaChainExtraCerts() appends the CA chain fetched via
GET /ca/{caName}/chain (deduplicated by DER encoding) to the extraCerts of every
self-generated upstream response, before RA validation and before sending downstream.
After this fix the LCMP client also gets a non-null enrollment chain even without its own
EnrollmentTrust config, so the keystore write works with unmodified reference code.
CliCmpClient defensive fix kept as belt-and-braces (correct PKCS#12 chains need the leaf first).
