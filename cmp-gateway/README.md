# CMP-to-REST Gateway (RFC 9483 Lightweight CMP Profile)

A Java-based gateway that implements the **RFC 9483 Lightweight CMP Profile (LCMP)**. It receives CMP messages from end entities, translates them to REST API calls for the CEMA PKI system, and returns proper CMP responses.

This implementation leverages the **siemens/cmp-ra-component** library for all CMP message processing, protection (MAC + Signature), and certificate handling, ensuring full RFC 9483 compliance with minimal custom code.

## Features

- **RFC 9483 message processing**: `cmp-ra-component` parses and protects the
  LCMP message types it supports; the CEMA adapter maps the supported enrollment
  and revocation operations and leaves unavailable mappings explicit.
- **Dual Protection**: Automatically handles both MAC-based and Signature-based protection via `cmp-ra-component`.
- **REST Integration**: Translates CMP requests to CEMA RA REST API calls (`/ca/{ca}/template/{tpl}/issue`, etc.).
- **Flexible Authentication**: Supports Client Certificate (PKCS#12) authentication with HTTP Basic Auth fallback.
- **CSRF Handling**: Automatically retrieves and manages CSRF tokens from the RA.
- **Synchronous EE Communication**: End Entities receive immediate responses; a
  pending CEMA issuance is polled by the gateway before returning the CMP result.
- **Configurable**: Easy setup via `gateway.properties`.

## Prerequisites

Before running the gateway, ensure you have the following installed on your Windows machine:

1.  **Java Development Kit (JDK)**: Version 17 or higher.
    *   Verify: `java -version`
2.  **Git**: To clone the repository (if not already done).
3.  **Gradle**: The project uses Gradle. You can use the Gradle Wrapper included in the `cmp-ra-component` project, but you need a Gradle installation to build the gateway itself if it doesn't have its own wrapper yet.
    *   *Recommendation*: Install Gradle via Chocolatey (`choco install gradle`) or download manually from [gradle.org](https://gradle.org/install/).
    *   Verify: `gradle -v`

## Project Structure

```text
/workspace
├── cmp-ra-component/       # Source code for siemens/cmp-ra-component (Dependency)
├── cmp-gateway/            # The Gateway Application (This Project)
│   ├── src/
│   │   └── main/java/...   # Java Source Code
│   ├── src/
│   │   └── main/resources/
│   │       └── gateway.properties # Configuration File
│   ├── build.gradle        # Build Script
│   └── README.md           # This File
└── plan.md                 # Implementation Plan
```

## Step-by-Step Setup Guide (PowerShell)

Follow these steps to build and run the gateway on Windows.

### Step 1: Build the `cmp-ra-component` Library

The gateway depends on the local `cmp-ra-component` library. You must build and publish it to your local Maven repository first.

1.  Open **PowerShell**.
2.  Navigate to the `cmp-ra-component` directory:
    ```powershell
    cd C:\path\to\workspace\cmp-ra-component
    ```
3.  Build and publish to local Maven repo:
    ```powershell
    .\gradlew.bat publishToMavenLocal
    ```
    *Note: If you don't have `gradlew.bat` in that folder, ensure you have Gradle installed globally and run `gradle publishToMavenLocal`.*

### Step 2: Configure the Gateway

1.  Navigate to the gateway resources folder:
    ```powershell
    cd C:\path\to\workspace\cmp-gateway\src\main\resources
    ```
2.  Open `gateway.properties` in a text editor (e.g., Notepad, VS Code).
3.  Update the following placeholders with your actual CEMA RA details:

    ```properties
    # --- CMP Server Settings ---
    cmp.server.port=9000
    cmp.server.path=/cmp

    # --- RA REST API Settings ---
    # Base URL of the CEMA RA Service
    ra.rest.base.url=https://localhost:5443/cema/ccm/svc/db.file/rest/v2

    # CA and Template Names (Update these!)
    ra.ca.name=MyTestCA
    ra.template.name=EndEntityTemplate
    ra.lookup.name=default

    # --- Authentication Settings ---
    # Options: "certificate" or "basic"
    ra.auth.type=certificate

    # If using Certificate Auth (PKCS#12)
    ra.auth.cert.path=C:/path/to/your/client-cert.p12
    ra.auth.cert.password=changeit

    # If using Basic Auth (Fallback)
    ra.auth.username=admin
    ra.auth.password=secret

    # Truststore containing the CEMA HTTPS server certificate or issuing CA
    auth.truststore.path=C:/path/to/cema-truststore.p12
    auth.truststore.password=truststore-password
    auth.truststore.type=PKCS12

    # CEMA application login user; may differ from HTTP BasicAuth username
    auth.login.user=TenantAdmin

    # --- CMP Protection (Handled by cmp-ra-component) ---
    # MAC Secret (Text format for testing)
    cmp.protection.mac.secret=TopSecretMacKey
    # Gateway Identity Alias (for Signature protection if needed)
    cmp.protection.identity.alias=gateway
    ```

### Step 3: Build the Gateway

1.  Navigate to the gateway project root:
    ```powershell
    cd C:\path\to\workspace\cmp-gateway
    ```
2.  Build the project:
    ```powershell
    gradle build
    ```
    *If you added a Gradle Wrapper to this project later, you can use `.\gradlew.bat build`.*

### Step 4: Run the Gateway

1.  Ensure the CEMA RA service is running and accessible at the configured URL.
2.  Run the application:
    ```powershell
    java -jar build/libs/cmp-gateway.jar
    ```
    *(Note: You may need to check `build/libs` for the exact JAR name if it differs).*

3.  You should see logs indicating the server has started:
    ```text
    INFO: CMP Gateway started on port 9000 at /cmp
    ```

## Testing the Gateway

You can test the gateway using a CMP client (like `openssl cmp` or a Java test client).

### Example: OpenSSL CMP Initial Request (IR)

*Prerequisite: You need a valid CMP configuration file (`openssl.cnf`) and credentials compatible with RFC 9483.*

```powershell
openssl cmp -srvaddr localhost:9000 -srppath /cmp `
  -certout new_cert.pem `
  -keyout new_key.pem `
  -subject "/CN=TestUser" `
  -ir
```

### Expected Behavior

1.  **Request**: The End Entity sends a CMP `IR` to `http://localhost:9000/cmp`.
2.  **Processing**:
    *   `cmp-ra-component` validates the MAC/Signature.
    *   For an IR without a subject public key, the Gateway uses the LCMP
        central-key-generation branch and performs a `POST` to
        `/ca/{ca}/template/{tpl}/generate`.
    *   For CRMF containing a subject public key, the Gateway enters the
        ordinary CRMF issuance adapter (currently an explicit stub because
        CEMA has no CRMF/POP REST operation).
3.  **Response**:
    *   If the RA issues immediately (201), the Gateway returns a CMP `IP` (Initialization Response) with the certificate and, for central key generation, the encrypted private key.
    *   If the RA delays (202), the Gateway internally polls the RA until the cert is ready, then returns the CMP `IP`.

## Troubleshooting

-   **Connection Refused**: Ensure the CEMA RA service is running on `https://localhost:5443`.
-   **Authentication Failed**: Check `gateway.properties`. If using client certs, ensure the PKCS#12 path is correct and the password matches.
-   **CSR Extraction Errors**: The logs will show if the gateway fails to parse the CMP message. Ensure your client is sending valid RFC 9483 messages.
-   **Gradle Issues**: If `gradle` commands fail, ensure `JAVA_HOME` is set correctly to JDK 17+.

## Architecture Notes

-   **Synchronous Design**: The interface between the End Entity and this Gateway is strictly synchronous. The Gateway handles any necessary asynchronous polling with the backend RA transparently.
-   **Logging**: Uses `java.util.logging`. Logs are printed to the console. Adjust levels in `gateway.properties` if needed (currently set to `INFO`).
-   **Current support boundary**:
    - `p10cr`: implemented through CEMA issue/auto-issue REST endpoints.
    - `rr`: implemented through CEMA revoke REST endpoint.
    - `poll`: handled by `cmp-ra-component`; pending REST issuance is completed internally.
    - `ir`, `cr`, and `kur`: routed as normal CRMF operations. Requests without a
      subject public key take the LCMP central-key-generation branch through
      `/ca/{ca}/template/{template}/generate`; the returned PKCS#8 private key is
      supplied to `cmp-ra-component`, which signs and encrypts it in the CMP
      response. Requests with a subject public key take the ordinary CRMF
      issuance branch.
    - Ordinary CRMF issuance and batched CRMF requests are explicit stubs because
      the current CEMA REST API has no operation that accepts CRMF/POP data.
    - `genm`, nested, cross-certification, key recovery, CA-key update, and
      announcement/CRL operations are not mapped to CEMA.

## License

This project utilizes the **siemens/cmp-ra-component** which is subject to its own license (typically EPL-2.0 or similar). Please refer to the `cmp-ra-component` repository for specific licensing details.
