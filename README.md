# ghostlock-tv

adb-to-root kernel exploit for the onn 4K Pro Google TV (jarvis2)
against CVE-2026-43499, the GhostLock futex PI use-after-free
(`5.15.196-android14-11`, build `ab14657224`). Locked bootloader,
verified boot green, dm-verity enforcing; root is per-boot.

Writeup: <https://acheronsec.com/research/adb-to-root-on-a-locked-android-tv>

## Run

```
adb connect <ip>:5555
python3 ghostlock_poc.py --host <ip>:5555 --bin ghostlock
```

Requirements: Python 3 (stdlib only), `adb` and `nc` on PATH, and the
`ghostlock` binary from the [releases](../../releases) page. A miss
panics the box; the runner survives the reboot and re-rolls. Expect a
hit within a few rolls of a fresh boot.

## Files

| file | what it is |
|---|---|
| `ghostlock_poc.py` | the runner: fire, survive panics, verify root, shell |
| `ghostlock` (release) | exploit binary, aarch64 static, `ab14657224` only |

## Notes

- No kernel filter: `--bin` must match the target kernel or you are
  bricking the box, not missing it. Other kernels: build from the
  GhostLock family sources (see the writeup).
- Never install system updates: kernel OTA ships the fix, no rollback.
- After a hit the framework dies within a minute (writeup: "The cost
  of root"); the box keeps working as a headless appliance.

## Reclaim knobs

The runner fires a fixed, device-proven reclaim environment
(defined in `ghostlock_poc.py`):

| knob | default | what it tunes |
|---|---|---|
| `CRED_ATTEMPTS` | 6 | cred-plan attempts per roll |
| `PREPARE_SLABS` | 32 | slabs pre-seeded before each walk |
| `MOVABLE_STORM_MB` | 128 | movable-page storm size |
| `PCP_DRAIN_BURST` | 24 | per-CPU page-list drain bursts |
| `PCP_COUNT_DRAIN_MB` | 8 | MB drained per burst |
| `DRAIN_KILLS` | 64 | victims killed to drop their pages |

The values are the tested configuration for this box's 2 GB geometry;
the rationale for each is in the writeup. A device with a different
memory geometry needs a re-tune, which means editing the source.

Authorized research on your own devices only.