# CarrotCast Lite updates

CarrotCast Lite is the stock-phone application, separate from the CarrotCast ROM release channel.

Current release: [CarrotCast Lite 0.19](https://github.com/go1sk1/CarrotCast/releases/tag/lite-v0.19) · [Download APK](https://github.com/go1sk1/CarrotCast/releases/download/lite-v0.19/CarrotCast-Lite-0.19.apk)

In Lite 0.18 or later, open **USB·무선 연결 시험 옵션 → CarrotCast Lite 앱 업데이트 → 업데이트 확인 → 다운로드·설치**. Stop mirroring before updating. Allow installation from this app when Android asks, then confirm the update in Android's installer. The APK uses the same package and signing key. In the dedicated emulator, update discovery, download, signature/hash verification and the installer prompt succeeded, but Google Play Protect then blocked installation as potentially harmful. Installation completion and post-upgrade settings retention are not verified; behavior on the S25+ remains unverified.

- Android package: `dev.carrotcast.stockusb` (continues existing stock-phone trial installations).
- Channel: [`stable.json`](stable.json).
- Release tags: `lite-v<version>`; asset names: `CarrotCast-Lite-<version>.apk`.
- Lite releases must use `--latest=false` to preserve the ROM latest release.
- The app verifies APK byte length, SHA-256, package/version, and the installed app signing identity before opening Android's installer.
- `available:false` means that no APK is offered by the channel; `available:true` includes the published release metadata.

A release entry uses `versionCode`, `versionName`, `url`, `bytes`, `sha256`, and `notes`. Publish and verify the APK asset before updating the feed. Never put credentials or private keys in this feed. The owner explicitly authorized publication of the bundled development-identity APK on 2026-11-22. This does not authorize publishing separate credential files or unrelated private data.
