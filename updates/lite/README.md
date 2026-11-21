# CarrotCast Lite updates

CarrotCast Lite is the stock-phone application, separate from the CarrotCast ROM release channel.

- Android package: `dev.carrotcast.stockusb` (continues existing stock-phone trial installations).
- Channel: [`stable.json`](stable.json).
- Release tags: `lite-v<version>`; asset names: `CarrotCast-Lite-<version>.apk`.
- Lite releases must use `--latest=false` to preserve the ROM latest release.
- The app verifies APK byte length, SHA-256, package/version, and the installed app signing identity before opening Android's installer.
- `available:false` explicitly means that no APK is currently published to this channel.

A release entry uses `versionCode`, `versionName`, `url`, `bytes`, `sha256`, and `notes`. Publish and verify the APK asset before changing the feed to `available:true`. Never put credentials or private keys in this feed. Developer test builds that bundle a vehicle identity/private key require an explicit distribution decision before any public upload.
