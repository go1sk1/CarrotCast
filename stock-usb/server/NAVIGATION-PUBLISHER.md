# External navigation publisher

## GitHub Actions

Comma Patch 0.9.13 uses `go1sk1/CarrotCast` directly. It sends the saved APK to a draft release, checks the asset digest, and queues the navigation publisher workflow. The workflow checks the draft and the approved Android signer before adding the asset to the public release and updating the signed Lite catalog.

In the repository's Actions settings, install the existing dedicated catalog key as the secret `NAVIGATION_CATALOG_SIGNING_PEM` and create the variable `NAVIGATION_APK_SIGNERS` with the SHA-256 fingerprints shown by the approved mirror phones. The phone operator supplies a fine-grained token for `go1sk1/CarrotCast` with Contents read/write. Comma Patch keeps it in memory for the current activity. Verify completion under **Actions → Publish external navigation APK**.

## Standalone HTTPS server (Comma Patch 0.9.12)

Run `navigation_publisher.py` as a single process on a host with Python 3.11+, `cryptography`, Java, and Android Build Tools. Expose only `POST /publish` through an HTTPS proxy to the loopback service. Configure a request body limit of 256 MiB and allow time for APK validation and GitHub upload.

| Server setting | Value |
| --- | --- |
| `PORT` | Loopback port, default 8751 |
| `AAPT`, `APKSIGNER_JAR`, `JAVA` | Build Tools and Java paths |
| `GITHUB_TOKEN` | Server-managed credential with Contents write access on `go1sk1/CarrotCast` |
| `CATALOG_SIGNING_KEY` | Dedicated RSA PEM matching the navigation public key in Lite |
| `CATALOG_PUBLIC_KEY` | Path to Lite's `companions/navigation-public.der.b64` |
| `PUBLISH_OPERATOR_TOKEN` | Random operator upload credential, at least 32 URL-safe characters |
| `PUBLISH_APK_SIGNERS` | Comma-separated SHA-256 signer fingerprints of approved mirror phones |

From Comma Patch, save a Lite APK, tap **배포 요청**, then enter the HTTPS endpoint and operator code. The APK signer fingerprint shown at save time is the value the server administrator approves. The Android signing key stays on the mirror phone.

The publisher uploads to the existing `external-navigation` release and verifies the GitHub asset digest before updating `updates/lite/navigation-managed.json`. An identical submission can be retried. Older Lite builds continue to read their existing catalog. Compatible Lite builds verify the catalog signature and APK identity before enabling the Android installer. Confirm that distribution of the vendor APK is permitted before posting it publicly.
