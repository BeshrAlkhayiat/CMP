# Why the gateway is NOT using the shared secret (PBM) - detailed explanation

Companion to ANALYSIS.md (root-cause of "validating the protection certificate failed").
This document explains the CONCEPTS and answers: "shouldn't it be using the shared secret?"
=> Yes, it should. It isn't, because the client never sent a PBM-protected message.

## 1. CMP message protection in 60 seconds
Every CMP message has a "protection" field proving authenticity/integrity. Modes:
- POPOSI: only proof-of-possession proof, whole message unprotected.
- Shared secret / PBM (RFC 4210 5.1.3.1.1): keyed MAC.
    key = KDF( transactionID || senderNonce || recipientNonce || sharedSecret )
    protection = HMAC/PKCS#7-SignedData over that key. NO certificates involved,
    NO trust anchors needed, NO SignatureProtectionValidator.
    Full enrolment needs the extra handshake step:
      EE --IR(pbm, secret=initialPassword)--> RA   (RA authenticates via MAC check)
      EE <--ip(certRep status=inputAccepted)--     (ip carries senderKID = salt)
      EE --rec(pbm, secret=KDF(oldSecret||salt))--> (confirms possession, "checkPBM")
      RA --cp(...)-->                               (final response, pbm checkPBM)
- Signature-based (RFC 4210 5.1.3.1.2/3): sender signs with its private KEY;
  receiver verifies signature against sender CERTIFICATE and must build a PKIX
  path from that certificate to trusted ANCHORS. This is where the failure occurs.

Which validator runs is decided by the senderKID/protection bits in the header:
  - senderKID = subjectKeyIdentifier (or issuerAndSerialNumber) => signature mode
    -> cmpracomponent.msgvalidation.SignatureProtectionValidator
  - senderKID = byte-string (transactionID-derived) / no cert => MAC mode
    -> MacProtectionValidator ("validating the protection with the shared secret ...")

## 2. Evidence the IR was signature-protected, not PBM
Log line:
  WARN ...msgvalidation.SignatureProtectionValidator - validating the protection certificate failed
SignatureProtectionValidator is instantiated ONLY when the incoming message is
certificate-protected (see cmp-ra-component msgvalidation package). A PBM message
would have produced MacProtectionValidator activity instead. Conclusion: despite
gateway-p10-pbm.yaml, the LightweightCmpRa client sent a SIGNATURE-protected IR.

Reason in LCMP client code (cmp-client-component CmpClient/CmpConfigurationAdapterBase):
when a signer credential is available (config 'signer:' / 'signerKey:' or a key
entry usable as signer in the referenced keystore), it takes precedence over
'password:' shared-secret protection. To FORCE PBM the client config must have NO
signer credential at all (and usePbm:true / password set). Additionally LCMP uses
PBMOppf (RFC 9480 OPKI) when 'pbmProtocol: genm-opkp' is configured.

## 3. What the gateway does with each mode (current code)
File: cmp-gateway/src/main/java/com/siemens/pki/cmpgateway/server/CmpGateway.java
- MAC-protected request (working path today):
    RestUpstream.buildReusedCredentialContext() detects !isSignatureProtectedRequest(),
    returns null -> the RA component keeps the REQUEST's CredentialValidationDatabase
    entry (built by the inbound InputValidator from getInitialSharedSecret()) for the
    RESPONSE validation too -> PBM response validated with the same secret. OK.
- Signature-protected request (broken path today):
    protectUpstreamResponse() must produce a signature-protected CertRep. It tries to
    ECHO the EE signer certificate as extraCerts[0] (buildEchoedExtraCertsInterface)
    and re-sign with the matching key (reSignWithClientKey). But:
      * the EE private key is not in ClientAuthCert-CEMA-Admin.p12 -> cannot sign;
      * even if it could, the RA component re-validates everything returned from the
        UpstreamExchange callback (CmpRaUpstream.handleRequest -> InputValidator ->
        SignatureProtectionValidator): extraCerts[0] must build a PKIX path to
        getTrustedCertificates() = auto-fetched CEMA User CA / Root CA chain.
        An EE enrollment cert (self-signed test cert or CA cert under a different PKI)
        fails path building -> "validating the protection certificate failed".
    NOTE: the echo branch also sets leafCertAcceptable(true) on its OWN interface, but
    the RA component's TrustCredentialAdapter.validateCertAgainstTrust() in 4.3.0 does
    NOT consult isLeafCertAcceptable for the upstream INPUT verification and treats
    trustedCertificates==null as FAILURE (no skip). Hence the error persists.

## 4. Why the ThreadLocal workaround does not save the signature case
GatewayConfig.selfGeneratedUpstreamMessage / isProcessingSelfGeneratedUpstreamMessage()
returns null trust anchors while processing a self-generated CertRep. Two problems:
 a) In RA 4.3.0 null anchors => TrustManagerUtil.initTrustManager(null) throws inside
    try/catch => validateCertAgainstTrust returns null => still "failed" (verified in
    sources jar: TrustCredentialAdapter.validateCertAgainstTrust).
 b) The flag is cleared in the finally of handleRequest(); delayed responses processed
    via poll()/pollConfirmation run on another thread/callback and do not see it.

## 5. Bottom line / how to actually use the shared secret
The shared-secret path is fully functional TODAY (RestClient.getSharedSecret() reads
auth.sharedSecret from gateway.properties; inbound AND outbound PBM validation work).
To exercise it, make the CLIENT send PBM:
  1) Remove ALL signer material from the LCMP client config/keystore used with
     gateway-p10-pbm.yaml (no 'signer:', no 'signerKey:', keystore without a usable
     private-key entry, e.g. point truststoreOnly-style at a cert-only store).
  2) Keep password: <same value as auth.sharedSecret> and senderNonce/recipients
     as-is; optionally pbmProtocol: genm-opkp for PBMOppf.
  3) Expect flow ir(pbm) -> ip(inputAccepted) -> [client must send rec(checkPBM)!]
     -> cp. CURRENT GAP: the gateway never sends the confirmation leg -
     RestClient.confirmIssuance() exists but is never called from processIr(), and
     there is no implicitConfirmation handling, so classic PBM enrolment will stall
     after 'ip'. That must be implemented before end-to-end PBM works.
Alternative long-term fix for signature mode (if clients insist on signing):
issue the GATEWAY a client certificate under CEMA-User-CA (or add the BoarderZone
chain to the upstream trust anchors) so the CertRep signer passes PKIX validation.

## 6. Quick runtime experiment to confirm section 2 (no code changes)
Run LCMP twice against the current gateway and compare logs:
  A) current config            -> WARN SignatureProtectionValidator (cert mode proven)
  B) config WITHOUT any signer -> look for INFO lines about shared secret/MAC in the
     gateway log (MacProtectionValidator path); if it proceeds past the ip step you
     have confirmed PBM works up to the missing rec/cp gap of section 5.3.
