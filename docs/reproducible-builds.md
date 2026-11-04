# Checking a Silo release

Anyone can rebuild the desktop app from source and check that a release contains
exactly that code and nothing else. You don't need to trust whoever built the
release, or GitHub.

## What is compared

The app's code lives in one archive, `app.asar`, plus libsignal's native module
next to it in `app.asar.unpacked`. Two builds of the same commit, on the same
operating system, produce the same files byte for byte: the archive stores no
timestamps or paths from the build machine, and `npm ci` installs exactly what
`package-lock.json` lists.

The Electron runtime around the archive comes from Electron's own releases.
electron-builder checks its download against Electron's published checksums, then
flips the fuses listed below, so the runtime is not byte-identical to upstream.
`node apps/desktop/scripts/check-package.mjs` reads the fuses back on Linux.

## Steps

Use the same operating system as the release you want to check, and Node 22.

```sh
git clone https://github.com/MichaelDamiano/silo && cd silo
git checkout v0.1.0            # the release tag
npm ci
npm run build -w @silo/protocol -w @silo/signal
npm run dist -w @silo/desktop
npm run verify-release -w @silo/desktop -- ~/Downloads/silo-0.1.0-linux-x64.tar.gz
```

`verify-release` accepts a `.tar.gz` or `.zip`, an unpacked app folder, or the
`app.asar` of an installed copy. It only extracts archives and never runs anything
from the download. For an AppImage, `.dmg` or Windows installer, install it and pass
its `resources/app.asar` (on macOS, `Silo.app/Contents/Resources/app.asar`).

It prints both hashes and either `OK` or the files that differ. Each release also
lists the `app.asar` hash for each platform in `SHA256SUMS.txt`.

## What the release build locks down

These are set in `apps/desktop/electron-builder.yml` and enforced at startup.

| Setting | Why |
| --- | --- |
| `RunAsNode` fuse off | `ELECTRON_RUN_AS_NODE=1 silo` can't be used to run arbitrary scripts as Silo |
| `EnableNodeOptionsEnvironmentVariable` off | `NODE_OPTIONS=--require evil.js` is ignored |
| `EnableNodeCliInspectArguments` off | `--inspect` can't attach a debugger to the main process |
| Debugger switches refused | `--remote-debugging-port` and similar make Silo exit, so nothing can drive a signed-in window |
| `EnableEmbeddedAsarIntegrityValidation` on, `OnlyLoadAppFromAsar` on | On macOS and Windows, the app refuses to start if `app.asar` was changed after the build. Linux doesn't support this check yet |
| `GrantFileProtocolExtraPrivileges` off | The page is served from `app://silo/`, which serves only the bundled files, never `file://` |
| `EnableCookieEncryption` on | Chromium's cookie store is encrypted with the OS keychain. Silo sets no cookies, but this keeps any from sitting on disk in plain text |
| DevTools and the Reload menu removed | Only in release builds; `npm run dev` keeps them |

The renderer also runs sandboxed with context isolation, a strict Content Security
Policy, no navigation, no pop-ups, no `<webview>`, every browser permission
denied, and no network access of its own: every request it makes other than to
`app://silo/` is cancelled. Only that page can call into the main process.

## Not done yet

- Code signing and notarization. Release builds are unsigned until signing keys
  are set up, so macOS and Windows will warn on first launch.
- Automatic updates. There are none; download new versions yourself and check them
  as above.
