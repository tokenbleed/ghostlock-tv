# GhostLock on a Locked Smart TV: porting CVE-2026-43499 to the onn 4K Pro

2026-10-27 · android · kernel · exploit-development · cve-2026-43499

I wanted to know if the public GhostLock bug could be ported onto a locked, verified-boot consumer Android TV box, with no bootloader unlock, no factory image, and nothing but the public exploit family to work from. And then whether the box would still be a usable TV afterwards. The answer to the first question is yes, and it runs from a stock machine against the stock build. The answer to the second is no, and the reason why is the most interesting finding in this whole project.

This work was verified end to end on hardware I own: a stock onn 4K Pro, verified boot green, bootloader locked, dm-verity enforcing, all system partitions stock. No system update was installed at any point during this work, which matters more than it sounds like it does, and I will get to that. The repository is deliberately small: the runner, this writeup, a readme, and nothing else. The exploit binary is not distributed; anyone reproducing this builds it from the GhostLock family sources for their own target kernel.

## The target

The onn 4K Pro is Walmart's house-brand Google TV. Board name jarvis2, Amlogic SoC, ~3 GB RAM, and a build chain that is pure GKI:

```
kernel:  5.15.196-android14-11-g3d26c188ef7e-ab14657224  (built 2026-01-03)
build:   onn/jarvis2/jarvis2:14/URO3.260203.035.A1/15640252:user/release-keys
patch:   2026-06-01
boot:    verifiedbootstate=green, flash.locked=1, veritymode=enforcing
```

The boot chain is what you would expect from a 2026 consumer device. No unlock token path ships for this box, and the Amlogic ROM enforces the bootloader, so the entire "flash a patched boot image" genre of Android rooting is off the table. Whatever root exists has to come from the running kernel, per boot, every boot.

The kernel cmdline is worth reading because it tells you what you are up against:

```
init_on_alloc=0  kasan.page_alloc.sample=10  stack_depot_disable=on
kvm-arm.mode=none  board=jarvis2
```

`init_on_alloc=0` matters: pages freed and reallocated keep their old contents, which is what lets a use-after-free walk find live data. The kasan knobs are sampling-mode only, not a real KASAN gate, so the primitives do not die on first touch.

## The bug

CVE-2026-43499 is a use-after-free in the futex PI requeue path, published in July 2026 as part of the GhostLock family. `futex_requeue()` moves waiters between lock wait queues. The pre-fix `remove_waiter()` and the requeue walk read `waiter->task` without pinning the task, so under enough controlled PI churn a waiter can be walked after the task it references is gone, and the walk dereferences freed task memory through `task->pi_lock` and `task->pi_waiters`.

The fix is in the same `android14-5.15` GKI branch HEAD today, as `waiter->task` / `waiter_task->pi_lock` revalidation. The device build predates it by six months. That makes this a porting exercise, not a variant discovery exercise: the bug is public, the primitive shape is documented across the ecosystem, and the work is in making it land on this build, on this box, with this RAM geometry.

## Rules I set for myself before writing any code

- No bootloader unlock attempts, no flashing, no partition writes.
- No system updates, ever. Not once.
- One exploit attempt per fresh boot. No unattended crasher loops.
- The device must remain a TV first. If a step kills the launcher, the step gets redesigned, not the expectations.

That last rule is the one I eventually could not keep, and the section that explains why is the one I would tell any replicator to read first.

## Porting

The ecosystem recipes (`ghostlock-k419-adapter`, `ghostlock-sabrina`, the oneplus Path A writeup) establish the method: per-build offsets, cross-checked against the device's own symbols. I derived the offsets from the boot image and then, after the first root, pulled a live `/proc/kallsyms` (19.5 MB with real addresses, after relaxing `kptr_restrict` from the privileged context) to verify every one:

- `selinux_state`: device table anchor `+0x29e9078`, verified by the AVC pair convention
- `init_cred` / `init_user_ns`: verified against the live symbol table
- kernel phys load `0x01810000`, confirmed against `/proc/iomem`

I deliberately do not ship the full kallsyms pull or the allocator statistics (`slabinfo`, `buddyinfo`, `pagetypeinfo`, `zoneinfo`, `vmstat`) in the public repository. They are the inputs the reclaim tuning below is derived from, and any re-port starts from pulling the same files off the live box: they belong on the box, not in the repo.

## The write primitive and the SELinux decision

The write primitive is the GhostLock rb_erase technique: walks over `rt_mutex_waiter` entries reinterpreted as rbtree nodes, each walk writing through the `pi_tree_entry` pivot into a chosen target. Two shapes matter:

```
child != NULL:  *TARGET = child; child->__rb_parent_color = parent|colour
                 (the two-store shape, used by the cred-swap walks)
child == NULL:  *TARGET = NULL, plus a colour walk if the victim pc is BLACK
                 (the zero-write shape)
```

The cred swap is the family recipe: walk 1 writes `task->cred`, walk 2 writes `task->real_cred`, both pointing at a fake cred on a spray page, with a follow-up repair write for the first-8-byte clobber the erase leaves behind. Both pointers must land before any exec, because `commit_creds` BUG_ONs unless cred equals real_cred.

The design decision specific to this port is the SELinux write.

The stock recipe writes 8 bytes of NULL at `selinux_state[0..7]`. That clears `enforcing`, `checkreqprot`, `initialized`, and five policy capability bytes in one stroke, and the device goes fully permissive. It also, it turns out, breaks the device in a way that takes a day of debugging to attribute. `initialized` is the sidtab's population flag. Zeroed, `getpeercon()` fails kernel-wide, and every binder service that registers after the hit is rejected by servicemanager. On a phone you notice when the UI dies. On a TV, where the entire device is binder services restarting each other, the box becomes a black paperweight that still answers ping.

So this port writes a pointer instead: the fake-cred address, spray page `+0xE00`, through the same child != NULL shape the cred walks use. The spray page is order-2 aligned, so byte 0 of the pointer is 0x00 and:

```
enforcing(+0)       = 0x00        permissive, as before
checkreqprot(+1)     = 0x0e        harmless under permissive
initialized(+2)     = nonzero     sidtab keeps working, binder keeps working
policycap[0..4]     = junk         harmless under permissive
```

Verified on device: after a pointer-write hit, services re-register their binder endpoints correctly, AVC lines print real contexts, and the box stays a functional TV while rooted. The zero-write boots could not do any of that.

## The reclaim environment

The part of a consumer-TV port that takes the actual time is not the primitive, it is making the reclaim geometry produce a landable page. On this box, 2 GB usable, the environment that works:

```
CRED_ATTEMPTS=6 PREPARE_SLABS=32 MOVABLE_STORM_MB=128 \
PCP_DRAIN_BURST=24 PCP_COUNT_DRAIN_MB=8 DRAIN_KILLS=64
```

The justifications, pulled from the box's own knobs: `min_free_kbytes=12288` and `watermark_scale_factor=80` mean the reclaim watermarks are tiny against the memory size, so a `PCP_COUNT_DRAIN_MB=8` drain bites immediately. `percpu_pagelist_high_fraction=0` means default pcp sizing, so the burst numbers are not fighting a raised high watermark. THP is `madvise`, not `always`, so the movable storm is pure migrate pressure with no collapse interference. And `sched_rt_period_us=1000000` / `sched_rt_runtime_us=950000` is the real constraint behind the walk timing: the nice-ladder rungs have to land inside the unthrottled 95% of each second.

Hit rate with that environment: about one land per two to three fresh boots, every observed hit inside the first six minutes of uptime. The all-time fastest was thirteen seconds after firing.

## Misses are fatal, and the box remembers

A miss is a walk landing on garbage while a PI lock is held. The oops fires with preemption off, and `panic_on_oops` is 1 by default on this build, so a miss is an immediate, unclean reboot. There is no surviving it, and `panic_on_oops=0` (which the delivery script sets, for later trips from the rooted context) cannot help mid-roll.

The box also has a memory. It runs f2fs, and enough unclean panic reboots in a day wedged mine into a corrupted-data boot loop that the recovery partition had to factory-reset its way out of. Twenty-six panics in one day is what that costs. The operational rules that fell out of this: one roll per fresh boot, a 45-second settle between rolls, and never, ever a cron of the crasher.

## Delivery, and the dead ends I want on the record

The root shell daemon is a `while` loop around `nc -L -p 13337 /system/bin/sh`, detached with nohup and `</dev/null`, re-arming after every connection. It is deliberately boring. Everything interesting about it is what it must not do:

- Never restart adbd. adbd runs `PR_SET_CHILD_SUBREAPER`. The exploit, the delivery script, and the daemon all live in its tree, so a `ctl.restart adbd` SIGKILLs the entire delivery mid-write. I lost a boot to this before I found the subreaper line in the boot log.
- Never reload SELinux policy at runtime. A `load` on selinuxfs rebuilds the sidtab and invalidates every live process's cached SID. system_server then runs as unlabeled until the next reboot. A reboot restores stock cleanly; nothing else does.
- Never call toybox `reboot` and trust it. On this build the builtin exits silently and nothing happens. The raw `reboot(2)` syscall works. I only found that after wondering why my box would not reboot.

## The cost of root: why the launcher dies

Here is the finding I would flag for anyone replicating this. About forty seconds after a clean hit, with no paint, no kills, nothing but the exploit and the daemon running, system_server dies:

```
E ServiceManager: android.os.DeadObjectException
E AndroidRuntime: *** FATAL EXCEPTION IN SYSTEM PROCESS: NetworkStats
I kernel: SELinux: security_sid_to_context_core: called before
          initial load_policy on unknown SID 1046
I binder: 702:900 transaction call to 233:0 failed ... -22
```

The chain: the hit's SELinux write leaves `selinux_state` pointing at spray-page memory that gets freed when the exploit process tree exits. The bytes in the state struct flip as the page is reused: enforcing comes back on, initialized goes back off, and `getpeercon()` starts failing kernel-wide again. servicemanager is alive but returns EINVAL on binder transactions. system_server's periodic NetworkStats poll catches the failure as a FATAL, and the framework dies. And init does not bring it back: `init.svc.*` properties go stale ("running" against dead pids), and `ctl.*` commands are accepted with rc=0 and spawn nothing. On some boots the framework survives for minutes, on this one it died at +43 seconds, but every post-hit boot I have observed eventually loses system_server this way.

So the honest final answer, after a month of trying: on this build, root and a live launcher are in tension. The rooted box works completely, ssh and the daemon and the full chroot toolchain, but as a headless appliance. If the launcher matters, power-cycle and use the box stock until the next roll.

The banner painter, for completeness: this box has no `/dev/fb0`, it is DRM-only, and DRM master is held by the composer HAL, not surfaceflinger. Taking master requires killing the HAL, and the HAL's death cascades: surfaceflinger exits, then system_server's statsd puller null-derefs on the dead SF and dies. Two tombstones and one dead framework later I removed the paint from the runner entirely. The painter source stays out of the runner (and out of the repository) because it is a demo, not a tool: every use costs a framework.

## The OTA threat

The fix for CVE-2026-43499 is in the branch HEAD that any kernel OTA for this box would ship. There is no downgrade: anti-rollback fuses, no unlock, no factory image to flash. Any accepted system update ends this exploit permanently, on this box, with no path back.

The defenses I run, in the order they actually protect:

1. Never accept updates. This is the whole game.
2. Router DNS sinkhole for `fes.google.com` and friends. Permanent, survives reboots, protects the unrooted windows too.
3. Per-boot iptables REJECT rules for the resolved update IPs, applied from the root daemon every rooted session. The runner does this automatically.

Layer 3 without layer 2 is a false comfort: every fresh boot and every panic reboot leaves a window where the updater is fully reachable and nobody has clicked the adb popup yet.

## What root does not get you

Even at uid 0, context kernel, full caps:

- TEE/TrustZone: Widevine L1 keys, keystore hardware keys, the `tee` partition. Not readable from the normal world.
- `/system`, `/vendor`, `/odm` writes: dm-verity enforces at mount. Raw reads are fine; writes corrupt the next boot.
- Binder from the shell contexts: `pm`, `am`, `cmd notification`, `screencap` are all policy-locked on this TV build, shell and kernel context both. APK installs go through the on-device Play Store or not at all.
- Persistence across reboots. Nothing survives. This is the whole per-boot model.

What does work: raw partition reads, kallsyms, ptrace of live processes from the daemon, full network egress, and a real Linux userland via the Alpine chroot.

## Tooling

The chroot is the answer to "how do I actually use this box":

- Alpine aarch64 rootfs under `/data/glroot` (persists across reboots; the bind mounts are per-boot)
- `PATH=/sbin:/bin:/usr/sbin:/usr/bin` exported inside, because the Android shell PATH does not include the chroot bins and every `cat` returning 127 is this
- dropbear chrooted, pubkey-only, root shell `/bin/bash`, port 22

Two warnings that cost me real hours, on the record for the next person:

1. toybox `tar` prints `had errors` on a fully successful rootfs extraction. Judge by the tree, not the message.
2. Never `rm -rf /data/glroot` while the bind mounts are attached. The rm recurses through `glroot/dev` into the live tmpfs and deletes `/dev`. I wiped `/dev/__properties__` this way: every `getprop` on the box died until the next power cycle. Unmount first, then delete, in that order, every time.

## The runner

`ghostlock_poc.py` is deliberately plain: stdlib, adb on PATH, one phase per function, nothing hidden. It is the pure exploit: connect, wait for authorization and boot, fire, survive the panic reboots, verify root through the daemon, drop into the shell. There is no kernel gate and no supported-target table: the binary you pass `--bin` owns the offsets, and pointing it at a kernel it was not built for is not a miss, it is a brick lottery. That is the operator's job now.

Design points worth keeping if anyone forks it:

- The runner refuses nothing and gates nothing. No filter means the operator verifies the kernel build by hand before every run: `--bin` must match `uname -r`.
- The daemon probe treats any successful TCP connect as alive, because the nc daemon serves one connection at a time and a busy daemon must never look dead. I double-fired an exploit onto an already-rooted box once before this rule existed.
- Misses are survived: the runner detects the panic reboot, waits for the adb popup (fresh boots re-show it, trust does not survive reboot), settles, and re-rolls within its budget.

## What this actually is

```
kernel          5.15.196-android14-11, pre-fix futex PI UAF (CVE-2026-43499)
primitive       rb_erase walk: cred swap + SELinux pointer write
target          onn 4K Pro (jarvis2), locked, verified boot green, verity enforcing
reclaim         32 prep slabs, 128 MB movable storm, pcp drains, 64 victim kills
hit rate        ~1 per 2-3 fresh boots, all lands inside 6 min of uptime
miss            always fatal (PI lock held, panic_on_oops=1), f2fs survives it
root model      per-boot, daemon on :13337, dropbear ssh on :22
persistence     none possible without breaking verified boot
cost            launcher dies ~43 s after hit (servicemanager/sidtab cascade)
```

## What's new here

- The pointer-write SELinux variant for this device class: preserving `initialized` while flipping `enforcing`, keeping binder registration alive on a TV where every service restart matters.
- The launcher-cost finding: the post-hit `selinux_state` bytes flip as the spray page is reused, servicemanager returns EINVAL, system_server dies on its next poll, and post-hit init never respawns it (stale `init.svc`, silent `ctl.*` no-ops).
- The delivery rules as load-bearing findings, not footnotes: adbd as `PR_SET_CHILD_SUBREAPER` (restart kills the delivery tree), policy reload invalidating live SIDs, toybox `reboot` being a silent no-op.
- The device research bundle: live kallsyms, allocator statistics, dropbox crash forensics, kernel cmdline, and the tombstones backing the display cascade. Kept off the public repo: every one of these is re-pullable from the live box once root lands.

## Related work

The GhostLock family repos this port builds on: `NebuSec/CyberMeowfia` (the original x86_64 landing, IonStack part II), `k-o-n-t-o-r/ghostlock-sabrina` (the closest device class to this box), `XiaoBaiLovesStirring/ghostlock-k419-adapter` (whose boot-window hint matches every hit I logged), and `JoinChang/ghostlock-oneplus` (the Path A UMH writeup this port's SELinux decision deliberately diverges from).

## Repository contents for replicators

- `ghostlock_poc.py`: the runner
- `WRITEUP.md`: this document
- `README.md`: reproduction and operational rules
- the exploit binary: not distributed; build it from the GhostLock family sources (Related work) for your target kernel, then pass `--bin`

## Reproduction

```
adb connect <device-ip>:5555       # click Allow on the TV popup
python3 ghostlock_poc.py --host <device-ip>:5555 --bin <exploit-binary>
```

Expect one to ten rolls with panic reboots survived between them, a root daemon on :13337, an interactive root shell through it, and a box that keeps answering on the network while the framework dies around it. The launcher is a separate question, and this document is the current answer to it: not yet, not on this build, and the reason is written down above.

Authorized research on my own hardware only. The upstream fix exists and ships; the disclosure work here is the device-side story of what locked consumer TVs look like before their OEM ships it.

First published at hack.ec.