# GhostLock PoC (CVE-2026-43499)

Runner for the onn 4K Pro Google TV (jarvis2) port of the GhostLock
futex PI use-after-free. Target kernel: `ab14657224`
(5.15.196-android14-11, pre-fix). Locked bootloader, verified boot
green, dm-verity enforcing: root is per-boot, there is no persistence
without breaking the boot chain.

The full technical writeup (the port, the write primitive design,
why the SELinux write is a pointer write, the reclaim environment,
the delivery dead ends, the operational findings) is published at
**<https://acheronsec.com/research/ghostlock-onn-4k-pro>**. Read it
before running anything.

## Repository

- `ghostlock_poc.py` - the runner (Python 3, stdlib only, `adb` on PATH)
- `ghostlock_r18` - exploit binary (aarch64, static), built for kernel
  `ab14657224`: download from the releases page, not committed to the
  tree. It contains no device-specific data (no serials, no network
  identifiers; verified) and runs on any device with the same kernel
  build, i.e. any onn 4K Pro on the same OTA level.

## Usage

```
adb connect <device-ip>:5555        # click Allow on the TV popup
# grab the binary from the releases page, then:
python3 ghostlock_poc.py --host <device-ip>:5555 --bin ghostlock_r18
```

Flags:

- `--bin PATH` - exploit binary built for the target kernel (required).
  No kernel filter: the binary must match the target kernel. An
  unverified-offsets fire is not a miss, it is a brick lottery.
- `--rolls N` - exploit attempt budget (default 6)
- `--settle S` - seconds to settle after each panic reboot (default 45)
- `--env K=V` - extra exploit env, repeatable (e.g.
  `--env GHOST_SELINUX=0` for the cred-swap-only launcher-survival mode)
- `--no-shell` - do not drop into the interactive root shell

## Building the binary for another kernel

The release binary only works on the `ab14657224` kernel build. For
any other kernel you must build from the GhostLock family sources
(the repo list is in the writeup's Related work section) with your own
per-build offsets: extract them from the device's own `boot.img`
(`kallsyms`) and rebuild. The build is a static aarch64 cross-compile
with the Android NDK, no framework dependencies:

```
aarch64-linux-android35-clang -O2 -static -pthread \
  <family sources> -o ghostlock
```

Verify the result the same way this repo's release binary was
verified: `strings` on the binary for any identifiers that should not
leave your machine, and a kernel-build check on the target before
every fire (`--bin` must match `uname -r`).

## What it does

1. Connects and waits for adb authorization (fresh boots re-show the
   popup; trust does not survive reboot on this device class).
2. Waits for boot, prints the kernel. No gate: you own the offsets.
3. Fires the exploit detached with the tuned reclaim environment.
4. A miss is always a fatal oops with a PI lock held: the box panics
   and reboots. The runner detects the reboot, waits for you to click
   the adb popup, settles, and re-rolls. Expect about one hit per two
   to three fresh boots; every observed hit landed inside the first
   six minutes of uptime.
5. On a hit, verifies `uid=0` through the on-device root daemon (port
   13337) and drops into an interactive root shell (`nc`).

## Operational notes

- The daemon (`nc -L -p 13337 /system/bin/sh`, detached with nohup)
   re-arms after every connection; any successful TCP connect means
   root is alive. The runner never fires a second exploit instance
   onto a box that answers.
- Root is per-boot. After any reboot, re-run the runner (fresh boot =
   best odds).
- Never install system updates: the GKI branch HEAD carries the
   upstream fix, and any kernel OTA ends this exploit permanently on
   this box (anti-rollback, no unlock path).
- About 43 seconds after a clean hit the framework dies (the
   `selinux_state` bytes flip as the spray page is reused;
   servicemanager returns EINVAL and system_server goes down on its
   next poll). The rooted box keeps working as a headless appliance;
   see the writeup's "The cost of root" section. Power-cycle restores
   stock.
- Authorized research on your own devices only.