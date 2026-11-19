# AirDrop on macOS 27 (26B123, Intel/a2x) — status 2026-11-19

Three independent blockers were measured. Each is a 27-on-Intel compatibility gap, not one bug.

## Fixed / landed

| Item | State |
|---|---|
| Wi-Fi keychain `-25308` | Fixed via the code-identity carrier in the x86_64 dyld shared cache (`/usr/lib/hao/native-identities` → Apple arm64e `airportd`). Settings connects to saved networks with no password prompt. |
| sharingd Swift-async crash | Greatly reduced: `A2X_ASYNC_NEG_AREA=8` + tightened callback-door async test. `runs` went from ~7 (every minute) to 2 and stable; the residual is a Swift async frame-record arm64↔x86 gap. |
| AWDL get 207 | Root-caused and fixed in source (`02a96e6`): 27 renumbered AWDL get types, so 27's get 207 (`getChannelInfo`) hit 26's `getAwdlAfTxMode` (`length==8` guard) → EINVAL 22 → no AWDL peer. Remap get 207→206. Awaiting the GitHub Actions kext build to deploy. |

## Blockers

### 1. IDS device registration — hard boundary
- 27's `identityservicesd` is arm64e-only; on Intel it runs under Rosetta.
- iMessage/FaceTime accounts are Active/Online, but `hasRegIdentityContainer = 0`,
  `hasUnregIdentityContainer = 1`; no registration network traffic.
- Re-signing in to iCloud did not change it; routing identityservicesd through a2x crashes
  (runs=5). → sharingd logs `devices: ()`, `No devices registered`,
  `disable enhanced discovery`, so the Mac's AirDrop list cannot surface the iPhone.

### 2. AWDL get 207 → transfer fails (fix built, pending deploy)
- `ioreg SimpleBCM`: `AwdlLastType=207 AwdlLastKind=0 AwdlLastResult=22`.
- `awdl0` UP but peers=0; iPhone transfer never establishes a peer.

### 3. sharingd residual async crash
- `last exit 139` still occurs occasionally; area=8 + cb-door tightening reduced but did not
  eliminate it (Swift async frame-record translation gap).

## What is needed to finish

1. Deploy the Actions-built kext (`02a96e6`): expect `AwdlRemap207` to grow and
   `AwdlLastResult` to stop being 22.
2. If AWDL then peers, retest iPhone → Mac send (the Mac list stays empty because of IDS,
   but iPhone already sees the Mac and can initiate).
3. IDS remains a hard 27/Intel boundary unless Apple ships an x86_64 IDS daemon or a2x's
   translation of identityservicesd stops crashing.
