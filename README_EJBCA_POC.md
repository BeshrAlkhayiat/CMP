# PoC: OpenSSL CMP to EJBCA Bridge

This Proof of Concept demonstrates how to use `openssl cmp` to send certificate requests (`p10cr` or `ir`) to an internal EJBCA test CMP endpoint using the Siemens CMP RA Component.

## Architecture

```
[OpenSSL CMP Client] 
       |
       | (CMP over HTTP)
       v
[EjbcaCmpBridge] <--- Local Java HTTP Server (Port 8080)
       |
       | (CMP over HTTP - Pass Through)
       v
[EJBCA CA Server] <--- Your Internal Test Endpoint
```

**Mode:** This implementation uses **Mode A (Pass-Through)**. The RA component does not translate protocols; it validates the incoming CMP message and forwards the raw ASN.1 bytes to EJBCA, then returns the raw response.

## Prerequisites

1.  **Java 11+** (for `java.net.http.HttpClient`)
2.  **Maven** (to build the project)
3.  **OpenSSL 3.0+** (with CMP support enabled)
4.  **Running EJBCA Instance** with a CMP alias configured.

## Configuration Mapping

The code maps the parameters from your `CABackendParams-Kind-CMP.txt` file as follows:

| Parameter File Setting | Code Implementation | Value Used in PoC |
| :--- | :--- | :--- |
| `CMP.EndpointAddress` | Constructor Arg 1 | Passed at runtime |
| `AuthenticationSharedSecret` | Constructor Arg 2 | Passed at runtime |
| `CMP.Sender.KID` | Constructor Arg 3 | Optional |
| `CMP.HashAlgorithm` | `.setHashAlgorithm()` | **SHA256** (Upgraded from default SHA1) |
| `CMP.Dialect` | `.setDialect()` | **EJBCA** |
| `CMP.ImplicitConfirm` | `.setImplicitConfirm()` | **false** |
| `CMP.ProtocolVersion` | `.setProtocolVersion()` | **cmp2000** |

## Step 1: Build the Project

Navigate to the workspace and compile the Java files. You will need the Siemens CMP RA library and BouncyCastle on the classpath.

Assuming you have the necessary JARs in a `lib/` folder or via Maven:

```bash
# Compile the bridge
javac -cp "cmp-ra-component/target/*:lib/*" EjbcaCmpBridge.java
```

## Step 2: Run the Bridge

Start the bridge application, pointing it to your EJBCA instance.

```bash
# Syntax: java -cp ".:lib/*" EjbcaCmpBridge <EJBCA_URL> <SHARED_SECRET> [SENDER_KID]

java -cp ".:lib/*" EjbcaCmpBridge \
  "http://localhost:8080/ejbca/publicweb/cmp/myalias" \
  "myTopSecretPassword" \
  "myKeyId"
```

*   **EJBCA_URL**: The full URL to your EJBCA CMP servlet (e.g., `/ejbca/publicweb/cmp/<alias>`).
*   **SHARED_SECRET**: The reference password configured in EJBCA for this CMP alias.
*   **SENDER_KID**: (Optional) The Key ID if your EJBCA setup requires it for shared secret lookup.

The application will start a local server on **http://localhost:8080/cmp**.

## Step 3: Send Requests with OpenSSL

Now, use `openssl cmp` to talk to your **local bridge** instead of talking directly to EJBCA.

### Option A: Send an Initialization Request (IR)
Use this for the very first request to get initial credentials.

```bash
openssl cmp -server http://localhost:8080/cmp \
  -cacerts ejbca_ca.pem \
  -certout new_cert.pem \
  -keyout new_key.pem \
  -subject "/CN=TestUser/O=MyOrg" \
  -ir \
  -secret myTopSecretPassword \
  -kid myKeyId \
  -digest sha256
```

### Option B: Send a PKCS#10 Certificate Request (P10CR)
Use this if you already have a key and CSR.

1.  **Generate Key and CSR first:**
    ```bash
    openssl genrsa -out user.key 2048
    openssl req -new -key user.key -out user.csr -subj "/CN=TestUser/O=MyOrg"
    ```

2.  **Send the P10CR:**
    ```bash
    openssl cmp -server http://localhost:8080/cmp \
      -cacerts ejbca_ca.pem \
      -certout issued_cert.pem \
      -p10cr user.csr \
      -secret myTopSecretPassword \
      -kid myKeyId \
      -digest sha256
    ```

### Explanation of OpenSSL Flags:
*   `-server`: Points to the **local bridge**, not EJBCA directly.
*   `-secret` / `-kid`: Must match the arguments passed to the Java app. The bridge uses these to configure the RA Component's MAC protection.
*   `-digest sha256`: Must match the `SHA256` setting in the Java code (per your requirements).
*   `-ir` / `-p10cr`: The type of CMP request body to send.

## Troubleshooting

1.  **"Connection Refused"**: Ensure the Java bridge is running and listening on port 8080.
2.  **"MAC Verification Failed"**: Ensure the `-secret` and `-kid` in OpenSSL match the Java startup arguments exactly.
3.  **"Bad Algorithm"**: Ensure `-digest sha256` is used in OpenSSL, matching the Java config.
4.  **EJBCA Errors**: Check the EJBCA logs. The bridge simply forwards the bytes, so protocol errors usually originate at the CA.

## Next Steps

*   **Trust Anchors**: Currently, the PoC relies on Shared Secret (MAC) protection. For production, implement `TrustAnchor` loading in the Java code to validate EJBCA's signature on responses.
*   **HTTPS**: The local bridge currently runs on HTTP. For production, enable SSL on the `HttpServer` or place it behind Nginx/Apache.
*   **Logging**: Integrate a proper logging framework (SLF4J/Log4j) instead of `System.out.println`.
