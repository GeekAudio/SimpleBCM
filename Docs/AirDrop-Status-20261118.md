# AirDrop on a2x: current state (2026-11-18 evening)

Measured on macOS 27.2 / 26B123, Intel, a2x routing sharingd/ControlCenter/Finder.
This file records what is fixed, what blocks AirDrop, and the exact evidence.

## Fixed today (kept)

- SimpleBCM Wi-Fi stack: menu-bar icon, CURRENT_NETWORK(103), scan IE capacity, hidden bit,
  EventFilter 0x21, request-flow counters (`Legacy103Patched=1`).
- sharingd ControlCenter invocation crash (Swift async trampoline, `-16` path) — a fix exists in
  the local a2x source (`host.c`, signed `gdelta`, optional `A2X_ASYNC_NEG_AREA`); the shipped
  `/usr/local/libexec/sharingd` currently runs with `A2X_ASYNC_NEG_AREA=16`.
- sharingd's Wi-Fi state was stuck at `NotConnected` although en1 was connected; a restart of the
  job made `CUWiFiManager` report `NotConnected -> Connected`.
- Finder restored to the user's original dev host after an experiment replaced it with the
  system routed binary, which crashes in `libc++.1.0.dylib`.

## Current blockers (all measured)

1. **Finder cannot start the AirDrop advertise request.**
   ```
   [com.apple.sharing:AirDropNWClient] XPCResilientAsyncSequence[<private>] FAILED.
       Unable to recreate sequence. Throwing iterationError
   [com.apple.xpc] invalidated after the last release of the connection object
   ```
   `Sharing.framework` symbols involved:
   `SFAirDropClient.registerTransfersMonitor` → `SFXPCResilientAsyncSequence.makeIterator`.

2. **sharingd never advertises.**
   ```
   SDActivityAdvertiser
   Should Not Advertise Requesters: {()}
   Current Advertisement Payload: GOODBYE
   Advertising Enabled: NO / Is Advertising: NO
   ```
   The Bluetooth layer (`CBAdvertiser`) does Activate/Update with AirDrop hashes, but the Sharing
   layer keeps `GOODBYE` because no client ever requested advertising.

3. **sharingd still crashes on the async `-16` path** with some `A2X_ASYNC_NEG_AREA` values:
   ```
   [tramp] async 0x1001bf09c returned with sp -16: no async area extra 16
   FATAL: SIGSEGV at guest pc 0 / swift_job_runImpl+0x8c / rip=0
   ```
   Values tried and crashed: area 0, 8, 16 (`extra`), -8 (net 0). The correct compensation is not
   yet identified; the guest function is a Swift async entry
   (`pacibsp; orr x29,x29,#0x1000000000000000; sub sp,sp,#0x80`).

## Evidence locations

- `/tmp/sharingd-sweep.err` — sharingd crash records from the lab host (tramp lines + SIGSEGV).
- `/var/log/Finder-27-A2X.stderr` — Finder crash records (the system routed binary).
- sharingd job: `launchctl print gui/501/com.apple.sharingd` (`Program=/usr/local/libexec/sharingd`).
- Finder job: `~/Library/LaunchAgents/com.apple.Finder.plist` (dev host + `A2X_GUEST` original guest).

## Open work (parallel subagents, 2026-11-18)

1. `SFXPCResilientAsyncSequence` internals and why the sequence cannot be recreated.
2. A systematic async-stack diagnostic (record every async call's gdelta, x86 call site, [rsp]).
3. `swift_job_runImpl` / a2x trampoline convention (correct rsp handling for suspended async guests).
4. The advertise-request chain (who calls `resumeForReason:`, why requesters stay empty).
