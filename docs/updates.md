# Installing and updating Silo

## Installing (Windows)

Download `silo-<version>-win-x64.exe` from the latest GitHub release and run it.
It installs for your user only, so it doesn't ask for an administrator password,
and puts Silo in the Start menu and on the desktop. Your account and messages
stay in `%APPDATA%\Silo` and survive uninstalling and reinstalling.

Release builds aren't code-signed, so Windows SmartScreen shows "Windows
protected your PC" the first time. Check the download's hash against
`SHA256SUMS.txt` in the release first:

```powershell
Get-FileHash $HOME\Downloads\silo-0.2.0-win-x64.exe
```

If it matches, click **More info**, then **Run anyway**. Updates installed by Silo
itself don't show this warning.

## How automatic updates work

A few seconds after it starts, and every six hours, Silo fetches
`silo-update.json` from the latest GitHub release. It installs an update only when:

1. the file is signed by a release key built into this copy of Silo
   (`apps/desktop/src/main/update-config.ts`),
2. the version in it is newer than the one running, so an old release can't be
   replayed to downgrade anyone, and
3. the installer it downloads has exactly the SHA-256 the signed file lists. The
   hash is checked again right before the installer runs.

The release key never touches GitHub or the build machines. Someone who takes over
the GitHub account, a CI runner or the download path can publish files, but can't
get them installed. Hashes alone wouldn't do that, because whoever can replace the
installer can replace a hash file next to it.

On Windows, Silo downloads the update in the background and shows **Restart to
update**. The installer then runs silently and starts Silo again. On macOS and
Linux, Silo only says that a new version is out and opens the download page;
macOS can't replace an unsigned app by itself.

With **Send all traffic through Tor** on, update checks and downloads go through
Tor as well, on their own circuit. Otherwise GitHub sees your IP address when Silo
checks. Turn checks off under **Settings → Updates**.

Development builds (`npm run dev`) never update themselves.

### The repository has to be public

Silo downloads updates without signing in to GitHub, so it can't read releases of
a private repository; checks report that no signed release exists. Either make the
repository public, or publish releases to a separate public repository and point
`UPDATE_FEED` in `update-config.ts` at it.

## Publishing a release (maintainers)

Commands are for Windows PowerShell, from the repository folder. On macOS or
Linux use `npm` instead of `npm.cmd`.

### Once: create the release key

```powershell
npm.cmd ci
npm.cmd run release-key -w @silo/desktop
```

It asks for a passphrase, saves the encrypted private key to
`%USERPROFILE%\silo-release-key.pem`, and adds the public key to
`apps/desktop/src/main/update-config.ts`. Copy the `.pem` file to a USB stick or
password manager. If it's lost, nobody can sign updates for copies that only trust
it; if it's stolen along with the passphrase, someone can. Commit
`update-config.ts` and merge it.

Copies of Silo built before that commit have no key, so people install the first
release that has one by hand. Every later release reaches them automatically.

To replace a key, run `release-key` again with a new path: both keys are trusted
until you delete the old one from `update-config.ts` in a later release.

### Each release

1. Set the version and commit it:

   ```powershell
   npm.cmd version 0.2.0 -w @silo/desktop --no-git-tag-version
   git commit -am "Silo 0.2.0"
   git push
   ```

2. After it's merged, tag it. The Release workflow builds every platform and
   makes a draft release with `SHA256SUMS.txt`:

   ```powershell
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. Download `SHA256SUMS.txt` from the draft release, and sign it:

   ```powershell
   npm.cmd run sign-release -w @silo/desktop -- $HOME\Downloads\SHA256SUMS.txt 0.2.0 --notes "Replies and reactions"
   ```

   It writes `silo-update.json` next to `SHA256SUMS.txt`. For extra assurance,
   rebuild the release yourself first and run `verify-release` on it, as in
   [reproducible-builds.md](reproducible-builds.md), so you only sign code you
   checked.

4. Upload `silo-update.json` to the draft release, then click **Publish release**.
   Installed copies pick it up within six hours, or right away with **Check now**.

Publish only after `silo-update.json` is attached. A release without it is simply
ignored by installed copies, so nothing breaks, but they won't update until the
next release that has it.
