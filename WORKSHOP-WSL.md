# Workshop WSL Extension Candidate

- Tag: **`workshop-wsl-extension`**
- Date: **November 26, 2026**
Status: **workshop/development candidate; final acceptance is operator-owned**.

This candidate contains the prepared WSL/capture-mode and multi-file manual import
extension. Publication and tagging do not certify production readiness or complete
Windows/Npcap/physical-NIC qualification. The earlier `wsl-compatible-test-1` tag
is historical and is not updated by this publication.

## 1. Get The Exact Workshop Snapshot

For a new checkout, run in Ubuntu/WSL Bash:

```sh
git clone --single-branch --branch workshop-wsl-extension \
  https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon
cd /home/user/otalon
git describe --tags --exact-match
```

The result must be `workshop-wsl-extension`. A tag checkout is detached by design.
It does not follow later branch updates. Do not run `git pull` to update a detached
tag checkout. The `wsl-compatible` branch remains the moving development branch.

For an existing checkout, first preserve any local changes and review `git status`.
Do not reset, delete or overwrite configuration, custody, captures or volumes:

```sh
git fetch origin tag workshop-wsl-extension
git switch --detach workshop-wsl-extension
git describe --tags --exact-match
```

Use the repository's existing GitHub remote if it has another name. These commands
do not grant permission to discard local modifications or switch a running system.

## 2. Install Using The Matching Instructions

- Windows/WSL2: follow [INSTALL-WSL.md](INSTALL-WSL.md) from **step 2** after the
  tag checkout above. Step 1 there describes the alternative moving-branch checkout;
  do not create a second checkout or replace this tag merely to match that step.
- Native Linux: follow [INSTALL.md](INSTALL.md) from **step 2** after this checkout.
- Keep existing `.env.compose`, certificates, passwords, source credentials and
  initialized database volumes. Installer reruns preserve configured values.
- Boot intent is `CAPTURE_TYPE=NONE` or `LIVE`; new installations default to NONE.
  NONE does not start acquisition and still permits manual PCAP/PCAPNG imports.
- WSL requires the base plus WSL Compose overlay. WSL LIVE additionally requires
  the LIVE overlay and the separately owned, authorized Windows collector.
- First login uses the application's normal bootstrap/password-change flow.
  Complete the mandatory password change in the browser. Never share passwords or
  keys in chat, logs or screenshots; use an origin-scoped secure credential store.
- Use properly trusted TLS for acceptance. Do not disable certificate verification
  or change authentication to make a test pass.

## 3. Included Changes And Recorded Verification

- Explicit NONE/LIVE boot intent and deployment-owned native/WSL backend identity.
- Multi-file picker/drop queue with per-file conflict/force decisions, actual
  transfer progress and persisted-terminal ordering. Explicit refresh can recover
  a late terminal result for a known blocked owner without automatic resend.
- Default manual upload payload limit of 1024 MiB, with a bounded multipart
  envelope. Existing smaller configured limits and separate collector limits remain.
- Permanent numeric authenticated-write refusal is latched; exception-safe owner
  cleanup and controlled stop handling are included.
- Recorded source regressions: Capture 1188, API units 2099 and UI 1790 passes.
  Raw UI typecheck remains at 146 pre-existing diagnostics under the unchanged
  149-error ratchet. Installer checks retain existing root-dependent skips.
- Fresh isolated-image supplementary API checks imported independently constructed
  small PCAP and PCAPNG fixtures, conserved exact packet/byte/window/MAC/protocol
  metrics, and preserved canonical jobs and measurements after consumer recreation
  without reupload. This is not complete browser or real-Windows acceptance.

## 4. Known Limitations — Final Acceptance Still Required

**Shutdown is not yet qualified as graceful.** In the isolated actual-image LIVE
probe, native and WSL services exited with **137** after roughly **10.3 seconds**
under the default Docker stop grace, without an OOM flag. Child processes were
terminated, but this is forced termination, not clean shutdown proof. In-flight and
held-dependency custody/no-late-success acceptance remains open. Do not treat a
successful `docker stop` command or a healthy service as evidence that this passed.

Other uncompleted gates include:

- Real authenticated HTTPS picker/drop, invalid-file, conflict/force, cancellation,
  late exact-owner refresh and history/reload workflows. The isolated automation
  attempt stopped at an untrusted certificate and mandatory first-password change.
- Actual 600/1024 MiB PCAP/PCAPNG uploads through UI and API, plus-one/custom-limit
  rejection, chunked/envelope/disconnect cleanup and measured memory/no-OOM behavior.
- Sustained native LIVE readiness, real WSL accepted-chunk custody/metrics and
  historical capability-free inspection. WSL without a collector proves only its
  waiting state, not acquisition success.
- Complete Windows/Npcap/physical-NIC capture and end-to-end detector qualification.

Final operator acceptance owns these checks. Preserve evidence and report failures;
do not lower assertions, increase grace, delete retained data, or bypass TLS/auth to
label an unverified candidate green. Use only networks and systems you are authorized
to monitor; disruptive traffic or active scanning is not part of this checkout guide.
