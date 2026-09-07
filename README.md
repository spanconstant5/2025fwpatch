# 8965F1208000 EPS Patch

[English](#english) · [中文](#中文)

[![CI](https://github.com/Kev-ORG/8965F1208000-FW-PATCH/actions/workflows/ci.yml/badge.svg)](https://github.com/Kev-ORG/8965F1208000-FW-PATCH/actions/workflows/ci.yml)

This repository provides a deliberately narrow, comma-local workflow for the reviewed `8965F1208000` EPS on a stationary private bench. Its public commands are only `probe`, `patch`, and `restore`.

Verified working on a **2023 Toyota Corolla (US-made, VIN prefix 5)**.

# English

Offline 2025 evidence: `eps_patch.corolla_2025.verify_codeflash()` verifies the exact
Span acquisition without hardware or artifact writes. Its authority is
[the pinned Corolla report](https://github.com/kaikozlov/ghidra_rh850/blob/a747ee291b94ffecbee69cf062aec72b23c4dc8d/docs/variants/corolla-8965F1208000.md)
and related `verify_spanconstant_*` tests. The reconstructed F181 is
`02 || 8965F1208000[16] || 8A3111213000[16]`, with NUL padding. Runtime still
accepts only the existing `8A3111202000` secondary record. Source-sector equality
does not establish the 2025 route, payload runtime, or steering compatibility.
Set `COROLLA_EVIDENCE_ROOT` to that reference checkout and run
`python -m pytest tests/test_corolla_2025.py tests/test_envelope_pins.py`.
Without the variable, real-corpus tests explicitly skip; an invalid supplied path fails.

## 0. Risk Warning

Read this chapter before connecting a Panda or powering the EPS.

- This repository supports only the reviewed `8965F1208000` firmware, old-UDS transport, Flash layout, payload set, and stationary bench configuration. It is not a general ECU flasher.
- Flash erase/program can leave the EPS unavailable. Use stable bench power, preserve the original probe backups, and have a realistic external programmer or professional recovery plan before patching.
- A planned power cycle is part of the workflow. Unexpected external power loss while a writer is erasing or programming is outside the supported workflow. Treat the result as indeterminate; never automatically retry it.
- Run `patch` and `restore` only in a visible foreground interactive SSH TTY. Do not pipe input, run them in the background, wrap them in unattended automation, or automate the authorization response.
- Never edit, replace, choose, or manufacture `state.json`, reports, backups, incident directories, returned sectors, payload binaries, or `manifest.json`. These files are mutually bound safety evidence, not user configuration.
- A steering DTC, loss or return of assist, terminal silence, SSH loss, a timeout, or one UDS response does not prove whether Flash changed. Only a complete validated readback and semantic `PASS` report establish the supported result.
- Road testing, arbitrary targets, manual sector selection, automatic rollback, and general writer retries are outside scope.

If any displayed identity, sector address, source digest, candidate digest, CRC, payload digest, or transaction direction differs from the reviewed values, stop before authorizing the writer.

## 1. Detailed Operating Guide

### 1.1 What you need

- A clean local checkout of this repository.
- The stationary `8965F1208000` EPS bench with stable power.
- A comma and Panda connected exactly as used during the reviewed bench work.
- SSH access that returns after the vehicle/EPS/comma power cycle.
- Openpilot Python `3.12.3` or newer, but lower than `3.13`.
- A foreground interactive terminal for every `patch` and `restore` invocation.
- An external recovery method available before the first destructive operation.

The only optional CLI argument is `--serial <Panda serial>`. Use it when more than one Panda can be discovered; do not use it to bypass an identity mismatch.

### 1.2 Synchronize the checkout to comma with rsync

Keep application files and runtime evidence in separate sibling directories:

```text
/data/eps-patch/
├── app/          # synchronized repository checkout
└── artifacts/    # probe evidence, patch incidents, restore attempts
```

From the repository root on the laptop, replace `<comma-ip>` with the comma address and run:

```bash
ssh comma@<comma-ip> 'mkdir -p /data/eps-patch/app'

rsync -av \
  --exclude='.git/' \
  --exclude='.worktrees/' \
  --exclude='.venv/' \
  --exclude='__pycache__/' \
  --exclude='.pytest_cache/' \
  --exclude='tests/' \
  ./ comma@<comma-ip>:/data/eps-patch/app/
```

Notes:

- Do not use `--delete` against `/data/eps-patch/`. A broad delete can remove the sibling `/data/eps-patch/artifacts/` recovery evidence.
- Never synchronize a laptop artifact directory over `/data/eps-patch/artifacts/`.
- Do not copy a virtual environment, cache, old attempt, or incident into `app/`.
- `payload/build/*.bin` and `payload/build/manifest.json` are reviewed runtime inputs. Do not rebuild or replace them on comma.
- After updating code, preserve all existing artifacts. The program validates whether an existing attempt can safely resume.

Then connect and enter the application directory:

```bash
ssh comma@<comma-ip>
cd /data/eps-patch/app
```

### 1.3 Preflight before every invocation

Check Python and required imports:

```bash
python3.12 --version
python3.12 -c 'import panda; import opendbc.car.uds; import opendbc.car.isotp; from Crypto.Cipher import AES'
```

Stop the comma/openpilot session and verify that neither native nor Python `pandad` remains:

```bash
tmux kill-session -t comma
pidof pandad
pgrep -f 'selfdrive\.pandad\.pandad'
```

It is acceptable for `tmux kill-session` to say that the session does not exist. The two process queries must return no process. The script independently checks the same conditions before opening Panda hardware and fails closed if a result is missing or indeterminate.

Also verify stable EPS power, foreground SSH TTY, the intended Panda serial, and that the bench cannot move. Resolve every preflight error rather than bypassing it.

### 1.4 Probe once: collect read-only trusted evidence

Run `probe` once before `patch` or `restore`.

Use:

```bash
python3.12 eps_patch.py probe
```

Probe does not erase or program Flash. It performs the comprehensive read-only evidence workflow and installs trusted artifacts only after every host and payload check passes:

```text
/data/eps-patch/artifacts/probe/
├── faci-pe-cycle-report.json
├── original-sector-0x88000.bin
├── original-sector-0xf8000.bin
└── recovery-metadata.json
```

A semantic `PASS` binds the supported ECU identity, application and boot F181 values, Panda serial, reviewed payload, both original 32 KiB sectors, original instruction context, FACI `PRE → UNLOCKED → WINDOWS → CONFIGURED → RESTORED` snapshots, cleanup back to idle, DCRA observations, software CRC checks, and host-side validation.

The directory is created atomically only on PASS. If it already exists, a new probe is rejected before preflight or transport. Preserve it: these are the original target and CRC-sector backups used by restore.

If a complete probe stream has a non-PASS outcome, the command does not create `probe` evidence. It prints the DCRA entry/exit `CTL` and `COUT` values and atomically replaces this untrusted diagnostic:

```text
/data/eps-patch/artifacts/failures/last-probe-failure.json
```

That diagnostic includes identity, payload, outcome, magic, the complete DCRA observation, five FACI snapshots, and address/length/SHA-256/CRC32 summaries for both returned sectors. It contains no sector bytes and cannot authorize patch or restore. Preserve it and the terminal output for analysis; do not repeatedly run probe merely to collect more values.

### 1.5 Patch: one safe stage per invocation

Start or resume patch with the same command every time:

```bash
python3.12 eps_patch.py patch
```

Patch automatically loads the fixed trusted probe directory. It accepts no report, backup, sector, incident, payload, or artifact path. The intended direction is fixed: target sector (`0x88000`) first, then the CRC sector (`0xf8000`).

Each hardware-bearing invocation opens at most one Panda/UDS connection and executes at most one ECU payload. The initial attempt-binding invocation performs preflight but opens no transport. After a completed stage, the program atomically persists the exact next checkpoint, prints a prominent complete-power-cycle instruction, and exits normally. Because comma is powered by the vehicle, its SSH connection also disappears during the cycle. Do not wait in the dead terminal and do not try to continue that process.

For every requested cycle:

1. Let the command save its checkpoint and exit.
2. Switch off vehicle/EPS/comma power completely.
3. Wait for complete discharge.
4. Restore stable power and allow comma to boot.
5. Reconnect SSH.
6. Return to `/data/eps-patch/app`.
7. Rerun the same command: `python3.12 eps_patch.py patch`.

A UDS reset is not a substitute for the complete power cycle. The script trusts the human-performed cycle and resumes only the persisted next stage; it does not use wall-clock or boot-ID proof.

The normal patch sequence has five planned boundaries:

| Persisted completed stage | Named next stage after power cycle | What the next invocation performs |
|---|---|---|
| `PROBED` | `TARGET_PRECHECKED` | Read-only target CRC/DCRA precheck |
| `TARGET_PRECHECKED` | `TARGET_ARMED` | Target writer becomes eligible on the next invocation |
| `TARGET_COMMITTED` | `CRC_PRECHECKED` | Read-only CRC-sector precheck |
| `CRC_PRECHECKED` | `CRC_ARMED` | CRC writer becomes eligible on the next invocation |
| `CRC_COMMITTED` | `VERIFY_PENDING` | Final read-only verification becomes eligible |

The `*_PRECHECKED` invocations are read-only and never arm a writer. The writer runs only on a later invocation after a complete power cycle and a new human authorization.

### 1.6 Review and authorize a writer

Before a destructive payload is triggered, the terminal prints a separate block such as `WRITE-TARGET`, `WRITE-CRC`, or `RESTORE-SECTOR`, including the target identity, actual sector address, source digest, candidate digest, CRC value, and envelope digest.

Review the entire transaction. If it is exactly the expected operation, type only:

```text
YES
```

The authorization is exact uppercase `YES`. Lowercase, whitespace, an empty response, EOF, or any other text stops before writer arm. This authorizes only the displayed transaction; it does not authorize later stages, a retry, a different sector, or recovery.

After `YES`, do not infer progress from terminal activity. Wait for the command to return a validated state or error. If the connection fails after writer trigger, the state is deliberately recorded as indeterminate.

### 1.7 Interpret patch results

| Persisted result | Meaning | Operator action |
|---|---|---|
| planned checkpoint | The named stage completed and the next stage is persisted | Complete the requested power cycle, reconnect SSH, rerun the same `patch` command |
| `PASS` | Both candidate sectors were independently read back and CRC/DCRA validation passed | Preserve the complete artifact tree; continue only with stationary functional compatibility tests |
| `TARGET_INDETERMINATE` | Target writer was triggered but a complete valid result/readback was not received | Do not patch again; run `restore` only through the persisted incident workflow |
| `CRC_INDETERMINATE` | CRC writer was triggered but a complete valid result/readback was not received | Do not infer success from DTCs; an ordinary first occurrence gets one read-only classification, while later occurrences are restore-only unless they match the separate exact legacy exception |
| `RECOVERY_REQUIRED` | The attempt cannot safely continue as a patch | Stop patching and run the bound restore workflow |
| partial/unknown live state | Live Flash matches neither the complete reviewed source nor candidate classification | Stop all writers; preserve evidence and use external programmer or professional recovery |

PASS is a Flash-level result. It does not, by itself, prove that the EPS RX SecOC behavior is functionally bypassed; that requires a later stationary bench test with the complete system.

### 1.8 CRC writer response is indeterminate

UDS `7F 31 78` means RoutineControl Response Pending. On ISO-TP, a raw frame may begin with `0x03` because that byte is the single-frame payload length. Neither that response nor a timeout, NRC `0x31`, or broken payload stream proves whether CRC Flash changed.

#### Ordinary first indeterminate outcome

An ordinary first `CRC_INDETERMINATE` is eligible for one-time read-only reconciliation. After the requested complete power cycle, reconnect SSH and rerun `python3.12 eps_patch.py patch`. That invocation runs only the reviewed `live_read` payload: no FACI P/E, no writer arm, and no `YES` prompt. It reads both entire 32 KiB sectors and validates the exact identity, history, source/candidate digests, payload, and byte-for-byte classifications.

- If target equals the complete candidate and CRC equals the complete source, the program persists `CRC_PRECHECKED`. Complete the requested cycle, rerun `patch`, review `WRITE-CRC`, and decide whether to authorize that one new writer with exact uppercase `YES`.
- If target and CRC both equal their complete candidates, the program persists `CRC_COMMITTED`. It skips the writer; complete the requested cycle and rerun `patch` for final read-only verification.
- If either sector is partial/unknown, the identity/history/evidence is not exact, or live read is incomplete, the reconciliation fails without arming a writer. Preserve the incident and use restore or external recovery as directed.

A second ordinary `CRC_INDETERMINATE` is restore-only. It cannot receive another general reconciliation or writer retry.

#### Separate legacy exception

The separate legacy exception applies only to the already audited incident shape: exactly two earlier `CRC_INDETERMINATE` transitions ending in NRC `0x31` with raw frame `037f313100000000`, including the reviewed first reconciliation and writer evidence. It is not a general retry mechanism and a semantic near miss is rejected before hardware.

After a complete power cycle, reconnect SSH and rerun:

```bash
python3.12 eps_patch.py patch
```

For that exact legacy history, the eligible invocation runs only the reviewed read-only `live_read` payload, reads both entire 32 KiB sectors, and compares every byte with the bound source/candidate values:

- If it persists `CRC_PRECHECKED`, target equals the complete candidate and CRC equals the complete source. Perform the requested power cycle, rerun `patch`, review `WRITE-CRC`, and authorize the one permitted CRC writer with a new exact `YES`.
- If it persists `CRC_COMMITTED`, both sectors already equal the complete candidates. No CRC writer runs. Perform the requested power cycle and rerun `patch` for final read-only verification.
- If identity, history, evidence, readback, or either sector classification is partial/unknown, patch remains blocked. Preserve the original incident and use restore only after review.
- If the permitted CRC writer becomes `CRC_INDETERMINATE` again, all later patch invocations are rejected before preflight, Panda connection, or confirmation. The incident is restore-only.

Never edit or replace `state.json` to force this path. Its exact history and evidence bindings are part of the authorization.

### 1.9 Restore a persisted incident

Run restore with no selector:

```bash
python3.12 eps_patch.py restore
```

Restore discovers a recoverable local incident and binds it to the fixed semantic-PASS probe backups. It does not accept a backup path, incident path, state file, sector, or payload selection.

Before every restore writer arm, a separate invocation runs the read-only `live_read` payload and reads both complete sectors again. The host checks the exact ECU identity, incident scope, original backups, known candidates, completed restore history, and current live classification.

If both sectors may be affected, restore uses CRC sector (`0xf8000`) first, then the target sector (`0x88000`). This keeps the recovery direction fixed and matches the reviewed restore primitive. A typical two-sector restore advances across separate invocations:

```text
STARTED
  -> CRC_LIVE_PRECHECKED
  -> CRC_ARMED / CRC_COMMITTED
  -> TARGET_LIVE_PRECHECKED
  -> TARGET_ARMED / TARGET_COMMITTED
  -> PASS
```

Each read-only precheck, each writer, and the transition between sectors is separated by a persisted checkpoint and complete power cycle. After comma restarts, reconnect SSH and rerun the same command:

```bash
python3.12 eps_patch.py restore
```

Authorize only the displayed `RESTORE-SECTOR` transaction with exact uppercase `YES`. If restore reports an indeterminate writer, unknown/partial live state, identity/evidence mismatch, failed readback, or invalid history, stop. Do not retry `patch` or `restore`; preserve the artifacts and use an external programmer or professional recovery.

### 1.10 Preserve the evidence

After success or failure, copy the complete `/data/eps-patch/artifacts/` tree to archival storage without changing the comma copy. Preserve the trusted probe directory, all patch attempts, all restore attempts, every state file, reports, returned sectors, untrusted probe diagnostic, terminal transcript, software commit, payload manifest, Panda serial, and bench observations. Do not keep only the newest file.

## 2. Design Principles and How It Works

### 2.1 Minimal public interface

The CLI intentionally exposes only `probe`, `patch`, and `restore`, plus optional Panda serial selection. Operators cannot provide evidence paths, choose sectors, choose incidents, substitute payloads, or alter the artifact root. This removes a large class of accidental mismatches.

### 2.2 Semantic evidence instead of a JSON-file lock

The workflow automatically reads `/data/eps-patch/artifacts/probe/faci-pe-cycle-report.json`. It does not require moving that file to a laptop and back. Trust is based on its parsed semantic PASS fields and its binding to the original sector bytes, recovery metadata, exact ECU/application/boot identity, Panda, payload manifest, and reviewed envelope, not on a fixed digest of the JSON serialization.

Both persisted backups must have exact expected length, address, SHA-256 relationship, instruction context, and CRC meaning. Patch and restore reconstruct and validate these relationships before transport.

### 2.3 One payload and one connection per invocation

Every hardware invocation constructs one reviewed encrypted payload envelope, opens one Panda/UDS connection, executes at most one payload, validates its stream, persists the result, and closes. It does not execute a second payload through a new UDS session while the previous RAM runtime may still influence the ECU.

Read-only prechecks and destructive writers live in different invocations, separated by a complete power cycle. You rerun the same command until the stage completes.

### 2.4 Download envelope, trigger range, and actual sectors

Every retained shellcode payload is wrapped in an encrypted 4 KiB (`0x1000`) envelope downloaded to RAM at `0xFEBF0000`. The common UDS FF00 trigger uses the fixed range `0xE0000 / 0x8000` after the host validates the payload's actual-sector contract.

The trigger range is not a Flash destination. Specialized target and CRC payloads still read, erase, program, and return their fixed actual sectors:

- target sector: `0x88000`, length `0x8000`;
- CRC sector: `0xF8000`, length `0x8000`.

The operator never selects `0xE0000`, `0x88000`, or `0xF8000`. These values are fixed and cross-checked by the host, source contracts, binary manifest, payload stream, and state evidence.

### 2.5 ECU-local 32 KiB read-modify-write

RequestDownload is 4 KiB because it carries executable payload code, not a sector image. A 32 KiB sector is never uploaded from the host to SRAM. The fixed writer reads the live Flash sector into ECU SRAM, checks that it is the exact expected source, changes only the reviewed byte/CRC adjustment, calculates the candidate checks, and then performs the fixed-direction erase/program sequence.

The reviewed target change is a single control-flow byte in the `0x88000` sector. The aligned four-byte context at `0x88C60` changes from `1d 30 e0 d1` to `1d 30 e0 01`: only byte `0x88C63` changes from `0xD1` to `0x01`. It is the second byte of the 16-bit comparison at `0x88C62`; the branch at `0x88C64` is preserved and the comparison forces its verified fallthrough. The older `0x8E6C7` location is not this Corolla's patch address.

Because boot integrity covers that change, the CRC-sector adjustment word at `0xFFDEC` must also change. On the reviewed firmware the patched-prefix CRC is `0x22A0EB88` and the candidate adjustment word is `0xDD5F1477`, so the full Code Flash range CRC residue stays `0xFFFFFFFF`. This is why a complete patch requires both `0x88000` and `0xF8000` rather than only the instruction byte.

The current `original_sha256` and `patched_sha256` values in `eps_patch/manifest.py` are the digests of the reviewed target sector before and after this single-byte change. This patch point, the adjustment word, and the sector digests were captured from the actual bench vehicle and validated end to end with a full `probe → patch → verify` run.

### 2.6 FACI, CRC, DCRA, cleanup, and readback

The writer primitives retain the direction and sequence of the previously bench-validated `patch_v2` and `restore_v1` operations: fixed sector, fixed page count, fixed unlock and P/E entry/exit order, bounded masked polling, explicit status/error checks, watchdog handling, and cleanup back to idle.

Software CRC and DCRA observations serve different roles. The host verifies full returned sector CRC/SHA relationships; ECU-side DCRA measures the configured full Code Flash range and its adjustment behavior. Both original and candidate meanings are checked where the workflow requires them. A successful erase/program status alone is insufficient: the returned complete sector, expected changed bytes, CRC, DCRA state, and final idle/cleanup conditions must all validate.

Writer payloads are never automatically retried. After the trigger boundary, any incomplete or malformed outcome is persisted as indeterminate so a read-only or external recovery decision can be made without guessing.

### 2.7 Flash programming matches the manufacturer's Calibration Update Wizard

The writer's FACI flash-programming sequence is byte-identical to the flash shellcode in Toyota's Calibration Update Wizard (CUW) update packages. I extracted and disassembled the CUW erase/program payload (`*_erase.pt.bin` from the `8965F3...` update packages) in Ghidra and compared it register-by-register against `faci_dual.h`. Every register write, command byte, poll bit, and error mask matches:

- P/E entry: `FENTRYR` (`0xFFA10084`) `0xAA01`; `FHVE15`/`FHVE3` (`0xFFF8A430`/`0xFFF82410`) to `1`; `FAREASELC` (`0xFFA10020`) `0x3B00`; `FPROTR` (`0xFFA10088`) `0x5501`.
- Block Erase: `FSADDR` = address, then command-area writes `0x20` then `0xD0`.
- Program: `FSADDR` = address, command-area writes `0xE8`, `0x80`, then 16-bit data words paced on `FSTATR` bit 11 (SUSRDY), then `0xD0`.
- Ready/error polling: `FSTATR` bit 15 (FRDY), error mask `0x7040`, `FASTAT` bit 4 (CMDLK); Forced Stop `0xB3` on error.
- Runtime stubs at `0xFEBF1188` (watchdog), `0xFEBF11AC` (critical enter), `0xFEBF11D2` (critical exit).

Two differences are deliberate and stricter:

- FW-PATCH's `exit_pe` also writes `FENTRYR` `0xAA00` to leave P/E mode; the CUW shellcode's exit clears only `FHVE15`/`FHVE3` and `FPROTR` and relies on a reset.
- FW-PATCH's `failure_cleanup` issues Status Clear `0x50` in addition to Forced Stop `0xB3`.

"Byte-identical" covers the FACI sequence: the register writes and command bytes. The payload binaries are this repository's own shellcode, compiled from `payload/*.c`; they reproduce the manufacturer's programming behavior, not its machine code.

### 2.8 Atomic artifacts and immutable history

Reports, state transitions, intents, returned sectors, and recovery plans are written atomically and fsynced. Each transition binds the relevant prior state, exact identity, probe evidence, source/candidate digests, payload/envelope identity, transaction intent, and returned observations.

An unresolved historical incident blocks new patching even if a newer attempt exists. A restore closes an incident only with a PASS state bound to that exact incident history. Manual state edits, copied directories, or mismatched backups fail closed before transport.

### 2.9 What PASS does and does not mean

Probe PASS means the read-only evidence contract passed. Patch PASS means the final complete target and CRC sectors equal the reviewed candidates and the required CRC/DCRA checks passed. Restore PASS means the affected sectors were restored and validated against the bound originals.

Flash-level PASS is not a claim that every higher-level vehicle function is correct. RX SecOC compatibility must be evaluated afterward on the stationary bench by observing the intended openpilot/EPS behavior, network messages, diagnostics, and safe steering behavior. Do not move directly from Flash PASS to road testing.

## 3. Cross-Compilation and Porting to Other Bench ECUs

### 3.1 Build the V850 cross-toolchain image

The repository includes only the Docker build environment in `v850-cross-build/Dockerfile`; the repository's own `payload/build.sh` remains the payload build entry point.

Build the image from the repository root on a development computer:

```bash
docker build -t v850-gcc:latest v850-cross-build
```

The image is based on Ubuntu 22.04 and builds binutils 2.41 plus GCC 13.2.0 for the `v850-elf` target. Building the image requires network access and can take substantial time.

### 3.2 Rebuild retained payloads

Run the repository build script inside the image:

```bash
docker run --rm \
  -v "$PWD/payload:/src" \
  -w /src \
  v850-gcc:latest \
  sh -c 'TOOL_PREFIX=v850-elf- ./build.sh'
```

`payload/build.sh` compiles the retained probe, CRC, live-read, candidate-writer, and restore payloads; enforces the 4048-byte shellcode limit; regenerates `payload/build/manifest.json`; and removes object, ELF, map, and other intermediate files.

Do not build payloads on comma. Do not casually synchronize a local rebuild to the bench. A rebuild changes reviewed runtime inputs even when the C source looks unchanged.

### 3.3 Required review after every rebuild

Use a clean review branch and review all of the following before any bench synchronization:

1. Toolchain versions and reproducibility.
2. Every source digest recorded in `manifest.json`.
3. Every payload size and the 4048-byte boundary.
4. Every retained binary SHA-256 and the corresponding host loader pin.
5. Every 4096-byte encrypted envelope SHA-256 pin.
6. Link address, entrypoint, sections, symbols, and complete disassembly.
7. Absence of forbidden erase/program addresses in read-only payloads.
8. Fixed actual-sector constants and FF00 trigger-route tests.
9. FACI access widths, ordering, bounded polls, cleanup, and fault-model tests.
10. Focused payload/source-contract tests and the complete Python test suite.

If a binary or envelope pin is absent or stale, runtime loading must remain fail-closed. Never update a pin merely to make a test pass; independently review the artifact first.

### 3.4 Forking for another RH850 bench target

Related RH850 ECUs are likely to use a very similar overall research method: establish a read-only evidence path, understand the bootloader and Flash controller, build a bounded RAM payload, prove recovery first, then separate precheck, writer, readback, and restore into durable stages. That similarity does not make any current target-specific value portable.

Before adapting a fork, independently establish:

- exact ECU part number, firmware revision, CPU variant, endianness, image base, reset vectors, and address mapping;
- CAN bus, request/response IDs, UDS session order, timing, old/new transport variant, required DIDs, and reset behavior;
- SecurityAccess algorithm and secret, RequestDownload encoding, RAM allocation, authentication routine, and FF00 trigger behavior;
- bootloader exploit entry, runtime stubs, calling convention, stack, watchdog, CAN transmit registers, SRAM buffers, and payload-size constraints;
- Code Flash geometry, block/sector/page sizes, FACI register addresses and access widths, protection unlock, P/E entry and exit sequence, commands, error masks, polling, cleanup, and reset effects;
- the real firmware control-flow decision found through disassembly and bench evidence, rather than copying `0x8E6C7` or the `0xD1 -> 0x01` change;
- every boot-integrity mechanism: CRC/DCRA descriptors, covered range, seed, polynomial, reflection, byte/word order, adjustment words, signatures, secure boot, and failure behavior;
- read-only identity, complete original sector backups, and recovery metadata before any destructive experiment;
- independently reviewed fixed-direction patch and restore primitives, with restore proven before patching;
- new target manifests, binary/envelope pins, source contracts, protocol tests, fault models, artifact roots, target naming, and operator documentation;
- a disposable stationary bench, stable power, complete logs, and access to an external programmer.

The current addresses, UDS credentials, SecurityAccess material, shellcode, binaries, CRC constants, Flash geometry, candidates, manifests, and backups are not portable to another RH850 ECU. V850 compiler compatibility is not ECU compatibility.

## 4. FAQ

### Q1. Why did SSH disappear after a requested power cycle?

Comma is powered by the vehicle in this bench setup, so a complete vehicle/EPS cycle also turns comma off. The script has already saved the checkpoint and exited. Wait for full power-off and reboot, reconnect SSH, return to the app directory, and rerun the same command.

### Q2. Should I continue in the old terminal after comma loses power?

No. That SSH session is dead and no process can continue through comma power loss. Start a new SSH session after reboot and rerun the same command. Do not substitute a UDS reset for the requested cycle.

### Q3. Why does one command execute only one payload?

It avoids opening another UDS/Panda session while a prior RAM runtime may still affect the ECU. One payload is validated and persisted, then a complete power cycle creates a clean boundary before the next stage.

### Q4. What does exact uppercase `YES` authorize?

Only the single transaction printed immediately above the prompt: the named sector, direction, source, candidate, CRC, and envelope. It does not authorize a later writer, retry, restore, or different sector.

### Q5. Is terminal silence proof that Flash programming is still running?

No. Silence may mean polling, communication loss, a stopped payload, or a dead connection. Wait for the command result; if the post-trigger result is incomplete, preserve the indeterminate incident and follow its recovery path.

### Q6. What is `7F 31 78`, and why can a frame start with `0x03`?

`7F 31 78` is UDS RoutineControl Response Pending. In an ISO-TP single frame, `0x03` can be the payload length. The parser recognizes Pending, but the frame alone says nothing about final Flash state.

### Q7. Does NRC `0x31`, a timeout, or a broken stream prove whether Flash changed?

No. These are transport/control observations, not complete sector readback. The workflow records an indeterminate state unless a specifically reviewed read-only reconciliation can classify both sectors.

### Q8. Can steering DTCs or assist behavior determine CRC-sector state?

No. They are useful bench observations but cannot distinguish complete source, complete candidate, partial erase/program, or a different fault. Use full bound readback and CRC/DCRA validation.

### Q9. What should I do after `TARGET_INDETERMINATE`?

Do not run patch again. Preserve the incident and run `python3.12 eps_patch.py restore`; the restore workflow first performs identity and fresh live-read checks before any writer becomes eligible.

### Q10. What should I do after `CRC_INDETERMINATE`?

Do not assume whether CRC changed. Complete the requested power cycle. The ordinary first occurrence receives one read-only two-sector classification; source may permit one newly confirmed writer, candidate skips the writer, and partial/unknown stops. A second ordinary occurrence is restore-only unless the complete history matches the separate legacy exception.

### Q11. Why are the ordinary reconciliation and one historical exception not general retries?

The ordinary path is limited to the first indeterminate outcome and one read-only classification. The legacy path additionally requires an exact reviewed history, identity, four source/candidate digests, both complete live-read records, and reconstructed writer evidence. In both paths, live Flash, not the NRC, decides whether to skip a writer, allow a newly human-authorized writer, or stop; every semantic near miss fails closed.

### Q12. Can I edit or replace `state.json` to continue?

No. The complete immutable history is part of the safety decision. Editing, deleting, copying, or selecting another state invalidates evidence and can authorize the wrong direction. Preserve the files unchanged.

### Q13. Can I rerun probe after a trusted PASS directory exists?

No. The command rejects an existing trusted probe directory before hardware access. Preserve that original evidence; do not rename or delete it to force another probe.

### Q14. Why is restore CRC-before-target when both sectors may be affected?

That is the reviewed fixed restore order bound into the incident plan and implementation. It restores the boot-integrity sector first, then the target, with a fresh two-sector live read before each arm.

### Q15. What if restore becomes indeterminate?

Stop. Do not retry restore or patch. Preserve all evidence and use an external programmer or professional recovery method. An incomplete restore writer result cannot be safely guessed from ECU behavior.

### Q16. What if unexpected external power loss occurs during erase/program?

It is outside the supported workflow. Treat the affected writer as indeterminate, preserve power-loss timing and artifacts, and use external/professional recovery. The planned checkpoint model does not make mid-writer power loss retryable.

### Q17. Why is RequestDownload 4 KiB rather than 32 KiB?

The host downloads a 4 KiB executable envelope, not a sector image. The payload reads and modifies the live 32 KiB sector inside the ECU, avoiding an out-of-range 32 KiB upload and binding the candidate to live Flash.

### Q18. Why does the transaction show `0x88000` or `0xF8000` while FF00 uses `0xE0000`?

`0x88000` and `0xF8000` are the actual fixed sectors read or written by specialized payloads. `0xE0000 / 0x8000` is the common validated UDS trigger range. It is not the writer destination.

### Q19. Does Flash-level PASS prove RX SecOC is functionally bypassed on the bench?

No. It proves the reviewed Flash candidates and integrity checks. Verify the intended RX SecOC behavior separately on the stationary bench with openpilot, messages, diagnostics, and steering behavior before drawing a compatibility conclusion.

### Q20. Can I rebuild payload binaries and immediately use them?

No. A rebuild changes reviewed runtime inputs. Review sources, toolchain, sizes, disassembly, addresses, manifests, binary/envelope pins, focused tests, and the full suite before syncing anything to the bench.

### Q21. Can this repository be used unchanged on another RH850 EPS?

No. The overall method may be similar, but all identities, addresses, UDS behavior, SecurityAccess data, Flash controller details, integrity rules, payloads, candidates, and recovery evidence must be independently established.

### Q22. What evidence should be preserved after success or failure?

Keep the entire artifact tree, terminal transcript, exact Git commit, retained manifest/binaries, probe backups, every patch/restore attempt and state, returned sectors, Panda serial, power-cycle sequence, DTCs, and stationary bench observations. Never preserve only the final report.

### Q23. Does this repository's flash programming match the manufacturer's?

Yes. The FACI sequence is byte-identical to the flash shellcode in Toyota's Calibration Update Wizard packages, cross-verified in Ghidra against the `8965F3...` CUW erase/program payload. Two differences are stricter cleanup, not functional changes: `exit_pe` also writes `FENTRYR` `0xAA00`, and `failure_cleanup` issues Status Clear `0x50` in addition to Forced Stop `0xB3`. See Section 2.7.

# 中文

2025 离线证据：`eps_patch.corolla_2025.verify_codeflash()` 只验证精确的 Span
采集文件，不连接硬件，也不写入运行时证据。依据为
[固定版本的 Corolla 报告](https://github.com/kaikozlov/ghidra_rh850/blob/a747ee291b94ffecbee69cf062aec72b23c4dc8d/docs/variants/corolla-8965F1208000.md)
及相关 `verify_spanconstant_*` 测试。重建的 F181 为
`02 || 8965F1208000[16] || 8A3111213000[16]`，记录以 NUL 补齐。
运行时仍只接受原有的 `8A3111202000` 第二记录。源扇区一致不能证明 2025
路由、payload 运行环境或转向功能兼容。将 `COROLLA_EVIDENCE_ROOT` 指向参考仓库后，运行
`python -m pytest tests/test_corolla_2025.py tests/test_envelope_pins.py` 可验证真实采集文件。
未设置路径时明确跳过真实文件测试；提供无效路径则失败。

已在 **2024 款丰田 RAV4 Prime** 和 **2026 款丰田 Sienna(中国制造)** 上验证可用。

## 0. 风险警告

连接 Panda 或给 EPS 上电前，请先完整阅读本章。

- 本仓库只支持已经审查的 `8965F1208000` 固件、旧版 UDS 传输、Flash 布局、payload 集合和静止台架配置。它不是通用 ECU 刷写器。
- 擦除或写入 Flash 可能导致 EPS 不可用。开始 patch 前必须准备稳定台架电源、保留原始 probe 备份，并具备现实可用的外部编程器或专业恢复方案。
- 计划性断电重启是流程的一部分。writer 正在擦除或写入时发生意外外部断电，不属于支持范围；必须把结果视为不确定，绝不能自动重试。
- `patch` 和 `restore` 只能在可见、前台、可交互的 SSH TTY 中运行。不要通过管道输入、后台任务、无人值守自动化或自动回答确认提示运行。
- 绝不能编辑、替换、选择或伪造 `state.json`、报告、备份、incident 目录、回传扇区、payload 二进制或 `manifest.json`。这些文件是互相绑定的安全证据，不是用户配置。
- 转向 DTC、助力消失或恢复、终端无输出、SSH 断开、超时或单个 UDS 响应，都不能证明 Flash 是否改变。只有完整且验证通过的回读与语义 `PASS` 报告才是支持的判断依据。
- 道路测试、任意目标、手工选择扇区、自动回滚和通用 writer 重试均不在范围内。

如果屏幕显示的身份、扇区地址、source 摘要、candidate 摘要、CRC、payload 摘要或交易方向与已审查值不一致，必须在授权 writer 前停止。

## 1. 详细操作指南

### 1.1 所需条件

- 本仓库在电脑上的干净 checkout。
- 稳定供电的静止 `8965F1208000` EPS 台架。
- 按已审查台架接线方式连接的 comma 和 Panda。
- 车辆/EPS/comma 完整断电后能够重新建立的 SSH 连接。
- openpilot Python `3.12.3` 或更高版本，但必须低于 `3.13`。
- 每次运行 `patch` 和 `restore` 都使用前台可交互终端。
- 第一次破坏性操作前已经准备好外部恢复手段。

唯一的可选 CLI 参数是 `--serial <Panda serial>`。只有可能发现多个 Panda 时才使用；不能用它绕过身份不匹配。

### 1.2 使用 rsync 同步到 comma

应用文件和运行证据必须放在两个并列目录中：

```text
/data/eps-patch/
├── app/          # 同步过去的仓库代码
└── artifacts/    # probe 证据、patch incident、restore attempt
```

在电脑的仓库根目录中，把 `<comma-ip>` 替换为 comma 地址后运行：

```bash
ssh comma@<comma-ip> 'mkdir -p /data/eps-patch/app'

rsync -av \
  --exclude='.git/' \
  --exclude='.worktrees/' \
  --exclude='.venv/' \
  --exclude='__pycache__/' \
  --exclude='.pytest_cache/' \
  --exclude='tests/' \
  ./ comma@<comma-ip>:/data/eps-patch/app/
```

注意：

- 不要对 `/data/eps-patch/` 使用 `--delete`。范围过大的删除可能清除并列的 `/data/eps-patch/artifacts/` 恢复证据。
- 绝不能用电脑上的产物目录覆盖 `/data/eps-patch/artifacts/`。
- 不要把虚拟环境、缓存、旧 attempt 或 incident 复制到 `app/`。
- `payload/build/*.bin` 和 `payload/build/manifest.json` 是已审查的运行输入，不要在 comma 上重新构建或替换。
- 更新代码时保留所有已有 artifacts；程序会验证已有 attempt 是否可以安全继续。

然后连接 comma 并进入应用目录：

```bash
ssh comma@<comma-ip>
cd /data/eps-patch/app
```

### 1.3 每次运行前的 preflight

检查 Python 与依赖：

```bash
python3.12 --version
python3.12 -c 'import panda; import opendbc.car.uds; import opendbc.car.isotp; from Crypto.Cipher import AES'
```

停止 comma/openpilot 会话，并确认 native 与 Python `pandad` 都不存在：

```bash
tmux kill-session -t comma
pidof pandad
pgrep -f 'selfdrive\.pandad\.pandad'
```

如果 `tmux kill-session` 提示会话不存在，可以忽略；后面两个进程查询必须没有进程输出。脚本会在打开 Panda 硬件前独立检查同样的条件，任何缺失或不确定结果都会 fail closed。

同时确认 EPS 供电稳定、SSH 是前台交互 TTY、Panda serial 正确，并确保台架不能移动。所有 preflight 错误都应解决，不能绕过。

### 1.4 Probe 一次：建立只读可信证据

在 `patch` 或 `restore` 之前只运行一次 `probe`：

```bash
python3.12 eps_patch.py probe
```

Probe 绝不擦除或写入 Flash。它执行一次综合只读证据流程，只有 payload 与主机的全部检查都通过后，才安装可信文件：

```text
/data/eps-patch/artifacts/probe/
├── faci-pe-cycle-report.json
├── original-sector-0x88000.bin
├── original-sector-0xf8000.bin
└── recovery-metadata.json
```

语义 `PASS` 会绑定受支持的 ECU 身份、application 与 boot F181、Panda serial、已审查 payload、两个原始 32 KiB 扇区、原始指令上下文、FACI `PRE → UNLOCKED → WINDOWS → CONFIGURED → RESTORED` 快照、清理回 idle、DCRA 观察、软件 CRC 和主机验证。

只有 PASS 才会原子创建该目录。目录已经存在时，新 probe 会在 preflight 和传输前拒绝。必须保留它：其中是 restore 使用的原始 target 与 CRC 扇区备份。

如果完整 probe stream 的 outcome 不是 PASS，命令不会创建 `probe` 证据。它会在终端显示 DCRA 进入/退出的 `CTL` 与 `COUT`，并原子替换这个不可信诊断文件：

```text
/data/eps-patch/artifacts/failures/last-probe-failure.json
```

该诊断包含身份、payload、outcome、magic、完整 DCRA 观察、五个 FACI 快照，以及两个回传扇区的地址/长度/SHA-256/CRC32 摘要。它不包含扇区内容，也不能授权 patch 或 restore。保留它与终端输出用于分析；不要只是为了收集更多数值而反复运行 probe。

### 1.5 Patch：每次运行只执行一个安全阶段

每次开始或继续 patch，都运行同一条命令：

```bash
python3.12 eps_patch.py patch
```

Patch 自动加载固定的可信 probe 目录，不接受报告、备份、扇区、incident、payload 或产物路径。方向固定为先写 target 扇区（`0x88000`），再写 CRC 扇区（`0xf8000`）。

每次包含硬件操作的运行最多只打开一个 Panda/UDS 连接，并最多执行一个 ECU payload。初次绑定 attempt 的运行只做 preflight，不打开 transport。阶段完成后，程序会原子保存准确的下一 checkpoint，显示醒目的完整断电提示，然后正常退出。由于 comma 由车辆供电，断电时 SSH 也必然断开。不要在已经断开的终端里等待，也不要试图继续旧进程。

每次收到断电提示后都这样操作：

1. 让命令保存 checkpoint 并退出。
2. 完全关闭车辆/EPS/comma 电源。
3. 等待完全放电。
4. 恢复稳定电源，等待 comma 启动。
5. 重新连接 SSH。
6. 回到 `/data/eps-patch/app`。
7. 重新运行同一条命令：`python3.12 eps_patch.py patch`。

UDS reset 不能代替完整断电。脚本相信人类已经完成断电，只按照已保存的下一阶段继续；它不使用墙上时钟或 boot ID 证明断电。

正常 patch 有五个计划性边界：

| 已持久化完成阶段 | 断电重启后的指定下一阶段 | 下一次运行执行的操作 |
|---|---|---|
| `PROBED` | `TARGET_PRECHECKED` | 只读 target CRC/DCRA 预检 |
| `TARGET_PRECHECKED` | `TARGET_ARMED` | 下一次运行可以进入 target writer |
| `TARGET_COMMITTED` | `CRC_PRECHECKED` | 只读 CRC 扇区预检 |
| `CRC_PRECHECKED` | `CRC_ARMED` | 下一次运行可以进入 CRC writer |
| `CRC_COMMITTED` | `VERIFY_PENDING` | 下一次运行可以进入最终只读验证 |

两个 `*_PRECHECKED` 阶段只读，绝不 arm writer。writer 只能在完整断电之后的下一次运行中，经新的人工授权触发。

### 1.6 核对并授权 writer

触发破坏性 payload 前，终端会单独显示 `WRITE-TARGET`、`WRITE-CRC` 或 `RESTORE-SECTOR` 交易块，其中包含目标身份、实际扇区地址、source 摘要、candidate 摘要、CRC 和 envelope 摘要。

完整核对交易。如果它与预期完全一致，只输入：

```text
YES
```

授权必须是精确的大写 `YES`。小写、空白、空输入、EOF 或其他文本都会在 writer arm 前停止。这个输入只授权屏幕上的一笔交易，不授权后续阶段、重试、其他扇区或恢复。

输入 `YES` 后，不能用终端活动来推断进度。等待命令返回验证后的状态或错误。如果 writer 触发后连接失败，程序会把状态记录为不确定。

### 1.7 判断 patch 结果

| 持久化结果 | 含义 | 操作员动作 |
|---|---|---|
| 计划 checkpoint | 指定阶段完成，下一阶段已保存 | 完成提示的断电重启，重新连接 SSH，再运行同一条 `patch` 命令 |
| `PASS` | 两个 candidate 扇区都完成独立回读，并通过 CRC/DCRA | 保留完整 artifact 树；之后只做静止台架功能兼容性验证 |
| `TARGET_INDETERMINATE` | target writer 已触发，但没有收到完整有效结果/回读 | 不要再次 patch；只通过已保存 incident 运行 `restore` |
| `CRC_INDETERMINATE` | CRC writer 已触发，但没有收到完整有效结果/回读 | 不要用 DTC 推断；普通第一次允许一次只读分类，之后只能 restore，除非精确匹配独立的历史遗留例外 |
| `RECOVERY_REQUIRED` | 当前 attempt 不能作为 patch 安全继续 | 停止 patch，运行绑定的 restore 流程 |
| partial/unknown live state | 当前 Flash 不等于完整已审查 source 或 candidate | 停止所有 writer，保留证据，使用外部编程器或专业恢复 |

PASS 是 Flash 级结果，并不单独证明 EPS 的 RX SecOC 功能已经绕过；还需要在完整系统的静止台架上进行后续验证。

### 1.8 CRC writer 回传不确定

UDS `7F 31 78` 表示 RoutineControl Response Pending。ISO-TP 单帧的开头 `0x03` 可能只是 payload 长度。这个响应、超时、NRC `0x31` 或损坏的 payload stream 都不能证明 CRC Flash 是否改变。

#### 普通的第一次不确定结果

普通的第一次 `CRC_INDETERMINATE` 可以进入一次性只读判定。完成提示的完整断电后，重新连接 SSH，重新运行 `python3.12 eps_patch.py patch`。这次运行只执行已审查 `live_read` payload：不进入 FACI P/E、不 arm writer、也不显示 `YES`。它会读取两个完整 32 KiB 扇区，并核对精确身份、历史、source/candidate 摘要、payload 和逐字节分类。

- target 完整等于 candidate 且 CRC 完整等于 source：保存为 `CRC_PRECHECKED`。完成提示的断电，重新运行 `patch`，核对 `WRITE-CRC`，再决定是否用精确大写 `YES` 授权一次新的 writer。
- target 与 CRC 都完整等于各自 candidate：保存为 `CRC_COMMITTED`，跳过 writer。完成提示的断电，再运行 `patch` 做最终只读验证。
- 任一扇区为 partial/unknown、身份/历史/证据不精确，或 live read 不完整：只读判定失败且不 arm writer。保留 incident，按照程序指引 restore 或外部恢复。

普通流程第二次出现 `CRC_INDETERMINATE` 后只能 restore。它不能再次获得通用只读判定或 writer 重试。

#### 独立的历史遗留例外

独立的历史遗留例外只适用于已经审计过的事故：历史必须精确包含两次较早的 `CRC_INDETERMINATE`，最后是 NRC `0x31` 且 raw frame 为 `037f313100000000`，并包含已审查的第一次判定与 writer 证据。这不是通用重试机制，任何语义近似都会在硬件前拒绝。

完整断电后，重新连接 SSH，并再次运行：

```bash
python3.12 eps_patch.py patch
```

对于该精确历史，符合条件的这次运行只执行已审查的只读 `live_read` payload，读取两个完整 32 KiB 扇区，逐字节与绑定的 source/candidate 比较：

- 如果保存为 `CRC_PRECHECKED`：target 完整等于 candidate，CRC 完整等于 source。按提示完整断电，再运行 `patch`，核对 `WRITE-CRC`，并用新的精确 `YES` 授权唯一允许的一次 CRC writer。
- 如果保存为 `CRC_COMMITTED`：两个扇区都完整等于 candidate。不会再运行 CRC writer；按提示断电并再次运行 `patch`，完成最终只读验证。
- 如果身份、历史、证据、回读或任一扇区分类为 partial/unknown：patch 保持阻止。保留原 incident，只在审查后使用 restore。
- 如果这一次允许的 CRC writer 再次变成 `CRC_INDETERMINATE`：之后所有 patch 都会在 preflight、Panda 连接和确认前拒绝；该 incident 只能 restore。

绝不能编辑或替换 `state.json` 强制进入这条路径。精确历史与证据绑定就是授权条件的一部分。

### 1.9 Restore 恢复已保存 incident

运行不带选择器的 restore：

```bash
python3.12 eps_patch.py restore
```

Restore 自动发现本机可恢复 incident，并绑定固定语义 PASS probe 的原始备份。它不接受 backup path、incident path、state file、sector 或 payload 选择。

每次 restore writer arm 前，都会在单独一次运行中执行只读 `live_read`，重新读取两个完整扇区。主机会核对精确 ECU 身份、incident 范围、原始备份、已知 candidate、已完成 restore 历史和当前 live 分类。

如果两个扇区都可能受到影响，restore 固定先恢复 CRC 扇区（`0xf8000`），再恢复 target 扇区（`0x88000`）。这个方向固定，并与已审查 restore primitive 一致。典型双扇区 restore 会跨多次运行推进：

```text
STARTED
  -> CRC_LIVE_PRECHECKED
  -> CRC_ARMED / CRC_COMMITTED
  -> TARGET_LIVE_PRECHECKED
  -> TARGET_ARMED / TARGET_COMMITTED
  -> PASS
```

每次只读预检、每次 writer 以及两个扇区之间，都由持久化 checkpoint 与完整断电隔开。comma 重启后，重新连接 SSH，然后重新运行同一条命令：

```bash
python3.12 eps_patch.py restore
```

只能用精确大写 `YES` 授权屏幕显示的 `RESTORE-SECTOR`。如果 restore 报告 writer 不确定、live 状态未知/部分匹配、身份/证据不符、回读失败或历史无效，立即停止。不要重试 `patch` 或 `restore`；保留 artifacts，使用外部编程器或专业恢复。

### 1.10 保留完整证据

无论成功或失败，都应把完整 `/data/eps-patch/artifacts/` 树复制到归档存储，同时不要修改 comma 上的原件。保留可信 probe 目录、所有 patch attempt、所有 restore attempt、每个 state file、报告、回传扇区、不可信 probe 诊断、终端记录、软件 commit、payload manifest、Panda serial 与台架现象。不要只保留最新文件。

## 2. 脚本设计原则和工作原理

### 2.1 最小公开接口

CLI 故意只公开 `probe`、`patch`、`restore` 和可选 Panda serial。操作员不能提供证据路径、选择扇区、选择 incident、替换 payload 或改变 artifact root，从接口上消除大量误配风险。

### 2.2 使用语义证据，而不是锁死 JSON 文件

流程会自动读取 `/data/eps-patch/artifacts/probe/faci-pe-cycle-report.json`，不要求把文件传到电脑再传回。信任来自解析后的语义 PASS 字段，以及它与原始扇区字节、recovery metadata、精确 ECU/application/boot 身份、Panda、payload manifest 和已审查 envelope 的绑定，而不是 JSON 序列化文件的固定摘要。

两个持久化备份必须拥有精确长度、地址、SHA-256 关系、指令上下文和 CRC 含义。Patch 和 restore 会在传输前重建并验证这些关系。

### 2.3 每次运行一个 payload、一个连接

每次硬件运行只构造一个已审查加密 payload envelope，打开一个 Panda/UDS 连接，最多执行一个 payload，验证 stream，持久化结果并关闭。它不会在上一个 RAM runtime 可能仍影响 ECU 时，立即再开第二个 UDS 会话执行另一个 payload。

只读预检与破坏性 writer 分属不同运行，由完整断电隔开。你反复运行同一条命令，直到阶段完成。

### 2.4 下载 envelope、trigger range 与实际扇区

每个保留的 shellcode payload 都被封装为 4 KiB（`0x1000`）加密 envelope，下载到 RAM `0xFEBF0000`。主机核对 payload 的实际扇区合同后，使用固定 UDS FF00 trigger range `0xE0000 / 0x8000`。

trigger range 不是 Flash 目标。专用 target 与 CRC payload 始终读、擦、写并回传固定实际扇区：

- target 扇区：`0x88000`，长度 `0x8000`；
- CRC 扇区：`0xF8000`，长度 `0x8000`。

操作员不选择 `0xE0000`、`0x88000` 或 `0xF8000`。这些值由主机、source contract、binary manifest、payload stream 和 state evidence 多重固定与交叉验证。

### 2.5 ECU 内部完成 32 KiB read-modify-write

RequestDownload 是 4 KiB，因为主机下载的是可执行 payload，不是扇区镜像。32 KiB 扇区绝不会由主机上传到 SRAM。固定 writer 在 ECU 内读取 live Flash 扇区到 SRAM，确认它是精确预期 source，只改变已审查字节或 CRC 调整字，计算 candidate 检查，然后执行固定方向擦写。

已审查的 target 改动是 `0x88000` 扇区内的单个控制流字节。`0x88C60` 的对齐 4 字节上下文由 `1d 30 e0 d1` 变为 `1d 30 e0 01`：只有 `0x88C63` 从 `0xD1` 变成 `0x01`。它是 `0x88C62` 处 16 位比较指令的第二个字节；`0x88C64` 处的分支指令保持不变，比较结果强制进入验证成功的顺序路径。旧位置 `0x8E6C7` 不是本 Corolla 的 patch 地址。

由于 boot integrity 覆盖该变化，`0xFFDEC` 处 CRC 扇区调整字也必须改变。已审查固件上 patch 后的 prefix CRC 为 `0x22A0EB88`，candidate 调整字为 `0xDD5F1477`，使完整 Code Flash 范围 CRC residue 保持 `0xFFFFFFFF`。因此完整 patch 同时需要 `0x88000` 与 `0xF8000`，而不是只改一个指令字节。

`eps_patch/manifest.py` 中当前的 `original_sha256` 与 `patched_sha256` 就是已审查 target 扇区在这单个字节改动前后的摘要。该点位、调整字和扇区摘要都来自真实台架车辆，并通过完整的 `probe → patch → verify` 端到端验证。

### 2.6 FACI、CRC、DCRA、清理与回读

writer primitive 保留迁移前已经台架验证的 `patch_v2` 与 `restore_v1` 方向和顺序：固定扇区、固定页数、固定 unlock 与 P/E 进入/退出顺序、有限次 masked polling、显式状态/错误检查、watchdog 处理和清理回 idle。

软件 CRC 与 DCRA 观察承担不同职责。主机验证完整回传扇区的 CRC/SHA 关系；ECU 端 DCRA 测量配置的完整 Code Flash 范围及调整行为。流程会在相应阶段核对 original 与 candidate 含义。仅仅擦写状态成功还不够：完整回传扇区、预期变更字节、CRC、DCRA 状态和最终 idle/cleanup 都必须通过。

writer payload 绝不自动重试。越过 trigger 边界后，只要 outcome 不完整或格式错误，就持久化为不确定状态，让只读判定或外部恢复在不猜测的前提下进行。

### 2.7 刷写逻辑与原厂 Calibration Update Wizard 字节级一致

writer 的 FACI 刷写序列与原厂丰田 Calibration Update Wizard（CUW）更新包里的刷写 shellcode 字节级相同。我把 `8965F3...` 更新包的擦写 payload（`*_erase.pt.bin`）提取出来，在 Ghidra 里反汇编，并与 `faci_dual.h` 逐寄存器对照。每个寄存器写、命令字节、轮询位和错误掩码都一致：

- P/E 进入：`FENTRYR`（`0xFFA10084`）写 `0xAA01`；`FHVE15`/`FHVE3`（`0xFFF8A430`/`0xFFF82410`）写 `1`；`FAREASELC`（`0xFFA10020`）写 `0x3B00`；`FPROTR`（`0xFFA10088`）写 `0x5501`。
- Block Erase：`FSADDR` 写地址，然后命令区写 `0x20`、`0xD0`。
- Program：`FSADDR` 写地址，命令区写 `0xE8`、`0x80`，随后按 `FSTATR` bit 11（SUSRDY）节奏写 16 位数据字，最后写 `0xD0`。
- 就绪/错误轮询：`FSTATR` bit 15（FRDY）、错误掩码 `0x7040`、`FASTAT` bit 4（CMDLK）；出错时 Forced Stop `0xB3`。
- runtime stub 位于 `0xFEBF1188`（watchdog）、`0xFEBF11AC`（critical enter）、`0xFEBF11D2`（critical exit）。

两处差异都是刻意收紧，不是功能变化：

- FW-PATCH 的 `exit_pe` 额外写 `FENTRYR` `0xAA00` 退出 P/E 模式；CUW shellcode 的退出只清 `FHVE15`/`FHVE3` 和 `FPROTR`，依赖 reset 复位。
- FW-PATCH 的 `failure_cleanup` 在 Forced Stop `0xB3` 之外还执行 Status Clear `0x50`。

"字节级一致" 指的是 FACI 序列：寄存器写和命令字节。payload 二进制是本仓库自己的 shellcode，由 `payload/*.c` 编译而来；它们复现原厂的刷写行为，不是复刻原厂的机器码。

### 2.8 原子 artifacts 与不可变历史

报告、state transition、intent、回传扇区和 recovery plan 都采用原子写入与 fsync。每个 transition 会绑定相关前一状态、精确身份、probe 证据、source/candidate 摘要、payload/envelope 身份、交易 intent 与回传观察。

只要任何历史 incident 没有被绑定的 PASS restore 关闭，就会阻止新的 patch，即使存在更新 attempt。Restore 只有生成绑定到该精确 incident 历史的 PASS 才能关闭它。手工修改 state、复制目录或替换备份都会在传输前 fail closed。

### 2.9 PASS 的含义与边界

Probe PASS 表示只读证据合同通过；patch PASS 表示最终完整 target 与 CRC 扇区等于已审查 candidate，并通过所需 CRC/DCRA；restore PASS 表示受影响扇区恢复为绑定 original 且通过验证。

Flash 级 PASS 并不宣称所有上层车辆功能正确。RX SecOC 兼容性仍需在静止台架上继续观察预期 openpilot/EPS 行为、网络消息、诊断与安全转向表现。不能从 Flash PASS 直接进入道路测试。

## 3. 交叉编译环境与其他台架车型移植

### 3.1 构建 V850 交叉编译镜像

仓库只在 `v850-cross-build/Dockerfile` 中加入 Docker 构建环境；payload 构建入口仍是本仓库自己的 `payload/build.sh`。

在开发电脑的仓库根目录构建镜像：

```bash
docker build -t v850-gcc:latest v850-cross-build
```

镜像基于 Ubuntu 22.04，构建面向 `v850-elf` 的 binutils 2.41 与 GCC 13.2.0。构建镜像需要网络，并可能耗时较长。

### 3.2 重新构建保留 payload

在镜像中运行仓库构建脚本：

```bash
docker run --rm \
  -v "$PWD/payload:/src" \
  -w /src \
  v850-gcc:latest \
  sh -c 'TOOL_PREFIX=v850-elf- ./build.sh'
```

`payload/build.sh` 会编译保留的 probe、CRC、live-read、candidate-writer 与 restore payload，强制 4048-byte shellcode 上限，重新生成 `payload/build/manifest.json`，并删除 object、ELF、map 等中间文件。

不要在 comma 上构建 payload，也不要随意把本地重建结果同步到台架。即使 C 源看起来没有变化，重建也会改变已审查运行输入。

### 3.3 每次重建后的必要审查

必须在干净 review branch 中审查：

1. toolchain 版本与可重复性；
2. `manifest.json` 中记录的全部 source digest；
3. 每个 payload 大小及 4048-byte 边界；
4. 每个保留 binary SHA-256 及对应 host loader pin；
5. 每个 4096-byte 加密 envelope SHA-256 pin；
6. link address、entrypoint、section、symbol 与完整 disassembly；
7. 只读 payload 中不存在禁止的擦写地址；
8. 固定实际扇区常量与 FF00 trigger route 测试；
9. FACI 访问宽度、顺序、有限轮询、清理与 fault model；
10. 聚焦 payload/source-contract 测试与完整 Python 测试。

如果 binary 或 envelope pin 缺失或过期，运行时必须继续 fail closed。不能只是为了通过测试就更新 pin，必须先独立审查 artifact。

### 3.4 为其他 RH850 台架目标创建 fork

相关 RH850 ECU 很可能采用非常相似的整体研究办法：先建立只读证据路径，理解 bootloader 与 Flash controller，构建有限 RAM payload，先证明恢复，再把预检、writer、回读和 restore 分成可持久化阶段。但这种相似性不代表任何当前目标专用值可以移植。

移植 fork 前必须独立确认：

- 精确 ECU part number、firmware revision、CPU variant、endianness、image base、reset vector 与地址映射；
- CAN bus、请求/响应 ID、UDS session 顺序、timing、旧/新传输 variant、所需 DID 和 reset 行为；
- SecurityAccess 算法与 secret、RequestDownload 编码、RAM allocation、authentication routine 和 FF00 trigger 行为；
- bootloader exploit 入口、runtime stub、calling convention、stack、watchdog、CAN transmit register、SRAM buffer 与 payload 大小限制；
- Code Flash geometry、block/sector/page 大小、FACI register 地址及访问宽度、protection unlock、P/E 进入退出顺序、command、error mask、polling、cleanup 与 reset 影响；
- 通过 disassembly 与台架证据找到真实 firmware 控制流决策，不能复制 `0x8E6C7` 或 `0xD1 -> 0x01`；
- 所有 boot-integrity 机制，包括 CRC/DCRA descriptor、覆盖范围、seed、polynomial、reflection、byte/word order、adjustment word、signature、secure boot 与失败行为；
- 任何破坏性实验前的只读身份、完整原始扇区备份与 recovery metadata；
- 独立审查的固定方向 patch 和 restore primitive，并且先证明 restore 再 patch；
- 新的 target manifest、binary/envelope pin、source contract、protocol test、fault model、artifact root、target naming 与操作文档；
- 可牺牲的静止台架、稳定供电、完整日志与外部编程器。

当前地址、UDS credential、SecurityAccess 材料、shellcode、binary、CRC 常量、Flash geometry、candidate、manifest 与 backup 对其他 RH850 ECU 都不可移植。V850 编译兼容不等于 ECU 兼容。

## 4. 常见问题

### 问1：为什么提示断电后 SSH 消失了？

本台架中 comma 由车辆供电，所以完整车辆/EPS 断电也会关闭 comma。脚本已经保存 checkpoint 并退出。等待彻底断电与重启，重新连接 SSH，回到应用目录，再重新运行同一条命令。

### 问2：comma 断电后还能在原终端继续吗？

不能。SSH 已经断开，旧进程不可能跨过 comma 断电继续。重启后建立新的 SSH 会话并运行同一命令；不要用 UDS reset 代替要求的完整断电。

### 问3：为什么一条命令只执行一个 payload？

这是为了避免上一个 RAM runtime 仍可能影响 ECU 时，再打开另一个 UDS/Panda 会话。一个 payload 完成验证和持久化后，用完整断电建立干净边界，再进入下一阶段。

### 问4：精确大写 `YES` 授权了什么？

只授权提示上方显示的一笔交易：指定扇区、方向、source、candidate、CRC 与 envelope。不授权后续 writer、重试、restore 或其他扇区。

### 问5：终端一直没有输出，能证明 Flash 仍在写吗？

不能。无输出可能是轮询、通信丢失、payload 停止或连接死亡。等待命令结果；如果 trigger 后结果不完整，保留不确定 incident，并按它的恢复路径处理。

### 问6：`7F 31 78` 是什么，为什么 frame 可能以 `0x03` 开头？

`7F 31 78` 是 UDS RoutineControl Response Pending。在 ISO-TP single frame 中，`0x03` 可以是 payload 长度。解析器会识别 Pending，但该 frame 本身不能说明最终 Flash 状态。

### 问7：NRC `0x31`、超时或 stream 损坏能证明 Flash 是否改变吗？

不能。这些是传输/控制观察，不是完整扇区回读。除非有专门审查过的只读判定能够分类两个扇区，否则流程会记录不确定状态。

### 问8：转向 DTC 或助力表现能判断 CRC 扇区状态吗？

不能。它们是有用的台架现象，却无法区分完整 source、完整 candidate、部分擦写或其他故障。必须依赖绑定的完整回读与 CRC/DCRA。

### 问9：出现 `TARGET_INDETERMINATE` 后怎么办？

不要再运行 patch。保留 incident，运行 `python3.12 eps_patch.py restore`；restore 会先做身份与 fresh live-read 检查，之后 writer 才可能变为 eligible。

### 问10：出现 `CRC_INDETERMINATE` 后怎么办？

不要猜测 CRC 是否改变。完成提示的断电。普通第一次会得到一次只读双扇区分类：source 可以允许一次新确认 writer，candidate 会跳过 writer，partial/unknown 会停止。普通第二次只能 restore，除非完整历史精确匹配独立的历史遗留例外。

### 问11：为什么普通判定和一个历史例外都不属于通用重试？

普通路径仅限第一次不确定结果和一次只读分类；历史路径还要求精确审查历史、身份、四个 source/candidate 摘要、两个完整 live-read record 与重建的 writer 证据。两条路径都由 live Flash 而不是 NRC 决定跳过 writer、允许一次新人工授权 writer 或停止；任何语义近似都会 fail closed。

### 问12：能否编辑或替换 `state.json` 后继续？

不能。完整不可变历史属于安全决策。编辑、删除、复制或选择其他 state 可能授权错误方向，并会让证据失效。必须原样保留。

### 问13：已有可信 PASS 目录后还能重新运行 probe 吗？

不能。命令会在硬件访问前拒绝已有可信 probe 目录。保留原始证据，不要通过改名或删除来强制再次 probe。

### 问14：两个扇区都可能受影响时，为什么 restore 先 CRC 后 target？

这是 incident plan 与实现中固定的已审查 restore 顺序：先恢复 boot-integrity 扇区，再恢复 target；每次 arm 前都重新读取两个扇区。

### 问15：如果 restore 变为不确定状态怎么办？

立即停止。不要重试 restore 或 patch。保留全部证据，使用外部编程器或专业恢复。不能依据 ECU 表现猜测不完整 restore writer 的结果。

### 问16：擦写过程中发生意外外部断电怎么办？

这不在支持范围。把对应 writer 视为不确定，保留断电时间与 artifacts，使用外部/专业恢复。计划 checkpoint 机制不会让 writer 中途断电变得可重试。

### 问17：为什么 RequestDownload 是 4 KiB 而不是 32 KiB？

主机下载的是 4 KiB 可执行 envelope，不是扇区镜像。Payload 在 ECU 内读取并修改 live 32 KiB 扇区，避免超范围的 32 KiB 上传，并把 candidate 绑定到 live Flash。

### 问18：为什么交易显示 `0x88000` 或 `0xF8000`，FF00 却使用 `0xE0000`？

`0x88000` 和 `0xF8000` 是专用 payload 实际读写的固定扇区；`0xE0000 / 0x8000` 是公共、已验证的 UDS trigger range，不是 writer 目标地址。

### 问19：Flash 级 PASS 能证明台架 RX SecOC 已经功能性绕过吗？

不能。它证明已审查 Flash candidate 与完整性检查。还要在静止台架上结合 openpilot、消息、诊断和转向行为，单独验证预期 RX SecOC 行为后才能得出兼容性结论。

### 问20：可以重新构建 payload 后马上使用吗？

不能。重建会改变已审查运行输入。同步到台架前必须审查 source、toolchain、大小、disassembly、地址、manifest、binary/envelope pin、聚焦测试与完整测试。

### 问21：这个仓库能不修改就用于其他 RH850 EPS 吗？

不能。整体办法可能相似，但身份、地址、UDS 行为、SecurityAccess 数据、Flash controller、integrity 规则、payload、candidate 与 recovery evidence 都必须独立建立。

### 问22：成功或失败后应该保留哪些证据？

保留完整 artifact 树、终端记录、精确 Git commit、保留的 manifest/binary、probe backup、每次 patch/restore attempt 与 state、回传扇区、Panda serial、断电顺序、DTC 和静止台架观察。绝不能只保存最终报告。

### 问23：本仓库的刷写逻辑与原厂一致吗？

一致。FACI 序列与原厂丰田 Calibration Update Wizard 包里的刷写 shellcode 字节级相同，并针对 `8965F3...` CUW 擦写 payload 在 Ghidra 中交叉验证。两处差异都是更严格的清理，不是功能差异：`exit_pe` 额外写 `FENTRYR` `0xAA00`，`failure_cleanup` 在 Forced Stop `0xB3` 之外还执行 Status Clear `0x50`。参见第 2.7 节。
