#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for rmc-radiusd's guest-pass roles, with stand-ins for everything on the AP they talk to.

guestd: a stand-in idm (bound where the relay expects /var/run/idm), authd and cpd senders, the tunnel's portal
interface port (a TCP listener, or a closed port) and the status file, all in a temporary folder.
portal: an HTTP client and stand-in hostapd control sockets.

Usage: test_guest.py <command that runs rmc-radiusd or the host build> ...
The byte order of the messages follows the ELF file named last on the command line (qemu-mips runs a big-endian one).
"""
import array
import hashlib
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

CMD = sys.argv[1:]
if not CMD:
    sys.exit(__doc__)


def elf_endian(cmd):
    for arg in reversed(cmd):
        try:
            with open(arg, "rb") as f:
                head = f.read(6)
        except OSError:
            continue
        if head[:4] == b"\x7fELF":
            return ">" if head[5] == 2 else "<"
    return "="


E = elf_endian(CMD)
SLOW = 3 if len(CMD) > 1 else 1      # under qemu everything takes longer

REQ_LEN, REPLY_LEN = 0x2ec, 0x964
LAYOUTS = {"short": dict(pass_len=0x11, uuid=0x81, name=0xa6, name_len=0x21),
           "long": dict(pass_len=0x96, uuid=0x106, name=0x12b, name_len=0x4b)}

failures = 0
passed = 0


def check(cond, what):
    global failures, passed
    if cond:
        passed += 1
    else:
        failures += 1
        print("FAIL:", what)


def wait_for(cond, timeout=3.0):
    end = time.time() + timeout * SLOW
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def mac_bytes(text):
    return bytes(int(x, 16) for x in text.split(":"))


# ---- pass lists ---------------------------------------------------------------------------------------------------

class Passes:
    def __init__(self, path, generated=None):
        self.path = path
        self.salt = secrets.token_bytes(16)
        self.generated = int(time.time()) - 60 if generated is None else generated
        self.records = []

    def add(self, code, state=1, redeem_by=None, first_used=None, duration=3600, max_devices=2, macs=(), name=None):
        digits = code.replace("-", "").replace(" ", "")
        h = hashlib.sha256(self.salt + digits.encode()).hexdigest()
        u = str(uuid.uuid4())
        self.records.append(" ".join([
            h, u, str(state), "-" if redeem_by is None else str(redeem_by), "-" if first_used is None else str(first_used),
            str(duration), str(max_devices), ",".join(macs) if macs else "-",
            "-" if name is None else urllib.parse.quote(name, safe="")]))
        return u

    def write(self):
        tmp = self.path + ".new"
        with open(tmp, "w") as f:
            f.write("rmc-guests 1 %d %s\n" % (self.generated, self.salt.hex()))
            for r in self.records:
                f.write(r + "\n")
        os.chmod(tmp, 0o600)
        os.rename(tmp, self.path)


# ---- guestd -------------------------------------------------------------------------------------------------------

def request(seq, mac, passwd, layout, wlan=7, module=3, msg_id=5):
    L = LAYOUTS[layout]
    b = bytearray(REQ_LEN)
    struct.pack_into(E + "IIII", b, 0, module, msg_id, seq, REQ_LEN - 0x10)
    b[0x10:0x16] = mac_bytes(mac)
    struct.pack_into(E + "I", b, 0x18, wlan)
    p = passwd.encode()[:L["pass_len"] - 1]
    b[0x1c:0x1c + len(p)] = p
    return bytes(b)


def parse_reply(b, layout):
    L = LAYOUTS[layout]
    r = {}
    r["len"] = len(b)
    r["module"], r["id"], r["seq"], r["length"] = struct.unpack_from(E + "IIII", b, 0)
    r["mac"] = b[0x10:0x16]
    (r["code"], r["status"], r["expiry"], r["wlan"], r["maxdev"], r["session"], r["nmacs"]) = \
        struct.unpack_from(E + "IIIIIII", b, 0x18)
    r["macs"] = [b[0x34 + 6 * i:0x3a + 6 * i] for i in range(min(r["nmacs"], 10))]
    r["pass"] = b[0x70:0x70 + L["pass_len"]].split(b"\0")[0].decode(errors="replace")
    r["uuid"] = b[L["uuid"]:L["uuid"] + 0x25].split(b"\0")[0].decode(errors="replace")
    r["name"] = b[L["name"]:L["name"] + L["name_len"]].split(b"\0")[0].decode(errors="replace")
    return r


class Dgram:
    """A bound AF_UNIX datagram socket."""

    def __init__(self, path):
        self.path = path
        if os.path.exists(path):
            os.unlink(path)
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.s.bind(path)

    def send(self, to, data, fds=()):
        if fds:
            self.s.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))], 0, to)
        else:
            self.s.sendto(data, to)

    def recv(self, timeout=1.0):
        self.s.settimeout(timeout * SLOW)
        try:
            data, fds, _flags, addr = socket.recv_fds(self.s, 0x10000, 8)
            return data, addr, fds
        except (socket.timeout, BlockingIOError):
            return None, None, []

    def drain(self):
        while True:
            self.s.setblocking(False)
            try:
                self.s.recv(0x10000)
            except BlockingIOError:
                return
            finally:
                self.s.setblocking(True)

    def close(self):
        self.s.close()


class Guestd:
    def __init__(self, d, layout="long", status_kind="int", connected=True, portal=True, idm_answers=None,
                 passes=None, extra_env=None):
        self.d = d
        self.layout = layout
        self.idm_path = os.path.join(d, "idm")
        self.status = os.path.join(d, "status")
        self.passes_path = os.path.join(d, "guests")
        self.bindings = os.path.join(d, "guest-bindings")
        self.log = os.path.join(d, "guestd.log")
        self.status_kind = status_kind
        self.set_connected(connected)
        self.idm = Dgram(self.idm_path)
        self.idm_ino = os.stat(self.idm_path).st_ino
        self.authd = Dgram(os.path.join(d, "idm0"))
        self.portal = None
        self.portal_port = None
        self.set_portal(portal)
        self.passes = passes or Passes(self.passes_path)
        self.proc = None
        self.extra_env = extra_env or {}

    def set_connected(self, up):
        with open(self.status, "w") as f:
            if self.status_kind == "run":
                f.write("RUN\n" if up else "CONNECTING\n")
            else:
                f.write("1\n" if up else "0\n")

    def set_portal(self, up):
        if self.portal:
            self.portal.close()
            self.portal = None
        if up:
            self.portal = socket.socket()
            self.portal.bind(("127.0.0.1", self.portal_port or 0))
            self.portal.listen(16)
            self.portal_port = self.portal.getsockname()[1]
        elif self.portal_port is None:
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            self.portal_port = s.getsockname()[1]
            s.close()

    def start(self):
        self.passes.write()
        env = dict(os.environ, RMC_GUESTD_IDM=self.idm_path, RMC_GUESTD_PROBE_PORT=str(self.portal_port),
                   **self.extra_env)
        status = ("run:" if self.status_kind == "run" else "int:") + self.status
        self.proc = subprocess.Popen(CMD + ["guestd", "--passes", self.passes_path, "--bindings", self.bindings,
                                            "--layout", self.layout, "--status", status, "--log", self.log], env=env)
        ok = wait_for(lambda: self.taken(), 5)
        check(ok, "guestd took over the idm socket")
        return ok

    def taken(self):
        """The relay has idm's name (and is alive there), and idm is at idm.real."""
        try:
            if (os.stat(self.idm_path).st_ino == self.idm_ino
                    or os.stat(self.idm_path + ".real").st_ino != self.idm_ino):
                return False
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                probe.connect(self.idm_path)
                return True
            finally:
                probe.close()
        except OSError:
            return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(5 * SLOW)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                check(False, "guestd stopped on SIGTERM")

    def ask(self, seq, mac, passwd, timeout=1.0, wlan=7):
        self.authd.send(self.idm_path, request(seq, mac, passwd, self.layout, wlan=wlan))
        data, addr, fds = self.authd.recv(timeout)
        for fd in fds:
            os.close(fd)
        return (parse_reply(data, self.layout) if data else None), addr

    def bindings_lines(self):
        try:
            with open(self.bindings) as f:
                return [l.split() for l in f.read().splitlines() if l]
        except FileNotFoundError:
            return []

    def log_text(self):
        try:
            with open(self.log) as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def close(self):
        self.stop()
        self.idm.close()
        self.authd.close()
        if self.portal:
            self.portal.close()


def fresh_dir():
    d = tempfile.mkdtemp(prefix="rmc-guest-test-")
    return d


def test_relay():
    print("guestd: relaying while the controller is connected")
    g = Guestd(fresh_dir())
    try:
        if not g.start():
            return
        # id 3 (DpskLookup) from authd: unchanged to idm, idm's reply unchanged back
        msg = struct.pack(E + "IIII", 3, 3, 41, 0x30) + bytes(range(0x30))
        g.authd.send(g.idm_path, msg)
        data, addr, _ = g.idm.recv()
        check(data == msg, "id 3 reaches idm unchanged")
        check(addr is not None and addr.startswith(g.idm_path + ".rmc"), "id 3 comes from a relay socket (%r)" % addr)
        reply = struct.pack(E + "IIII", 3, 4, 41, 0x10) + b"R" * 0x10
        g.idm.send(addr, reply)
        data, raddr, _ = g.authd.recv()
        check(data == reply, "idm's reply reaches authd unchanged")
        check(raddr == g.idm_path + ".rmc", "the reply comes from the relay's socket (%r)" % raddr)
        authd_relay = addr

        # id 9 from cpd: its own relay socket
        cpd = Dgram(os.path.join(g.d, "cpd_idm.sock"))
        msg9 = struct.pack(E + "IIII", 2, 9, 5, 4) + b"cpd!"
        cpd.send(g.idm_path, msg9)
        data, addr, _ = g.idm.recv()
        check(data == msg9, "id 9 reaches idm unchanged")
        check(addr != authd_relay and addr.startswith(g.idm_path + ".rmc"), "cpd has its own relay socket")
        g.idm.send(addr, b"ok9")
        data, _, _ = cpd.recv()
        check(data == b"ok9", "idm's reply reaches cpd")
        cpd.close()

        # id 5 relayed while connected: idm answers, nothing local
        p = g.passes
        mac = "02:00:00:00:00:01"
        g.authd.send(g.idm_path, request(100, mac, "1234567890", g.layout))
        data, addr, _ = g.idm.recv()
        check(data is not None and struct.unpack_from(E + "I", data, 4)[0] == 5, "id 5 reaches idm while connected")
        real = bytearray(REPLY_LEN)
        struct.pack_into(E + "IIII", real, 0, 3, 6, 100, REPLY_LEN - 0x10)
        real[0x10:0x16] = mac_bytes(mac)
        struct.pack_into(E + "I", real, 0x18, 206)
        g.idm.send(addr, bytes(real))
        data, _, _ = g.authd.recv()
        check(data == bytes(real), "idm's id 6 reply reaches authd unchanged")
        data, _, _ = g.authd.recv(0.3)
        check(data is None, "no second (local) answer")
        check(g.bindings_lines() == [], "no bindings line for a relayed pass")

        # SCM_RIGHTS: idm's large replies carry a descriptor
        g.authd.send(g.idm_path, struct.pack(E + "IIII", 3, 11, 7, 0))
        data, addr, _ = g.idm.recv()
        r, w = os.pipe()
        g.idm.send(addr, struct.pack(E + "IIII", 3, 12, 7, 0), fds=[w])
        os.close(w)
        data, _, fds = g.authd.recv()
        check(len(fds) == 1, "a descriptor passes through the relay")
        if fds:
            os.write(fds[0], b"through")
            os.close(fds[0])
            check(os.read(r, 16) == b"through", "the descriptor is idm's pipe")
        os.close(r)

        # authd's descriptor to idm, too
        r, w = os.pipe()
        g.authd.send(g.idm_path, struct.pack(E + "IIII", 3, 13, 8, 0), fds=[w])
        os.close(w)
        data, addr, fds = g.idm.recv()
        check(len(fds) == 1, "a descriptor passes to idm")
        for fd in fds:
            os.close(fd)
        os.close(r)
        _ = p
    finally:
        g.close()


def check_ok_reply(r, mac, uuid_, seq, passwd, layout, macs=None, name="Guest", duration=3600, expiry=None):
    check(r is not None, "a reply")
    if r is None:
        return
    now = int(time.time())
    check(r["len"] == REPLY_LEN and r["length"] == REPLY_LEN - 0x10, "reply length 0x964 / 0x954")
    check(r["id"] == 6 and r["module"] == 3 and r["seq"] == seq, "reply id 6, module 3, seq %d (%r)" % (seq, r))
    check(r["code"] == 206 and r["status"] == 1, "code 206, status 1 (got %d, %d)" % (r["code"], r["status"]))
    check(r["mac"] == mac_bytes(mac), "reply MAC")
    if expiry is None:
        check(abs(r["expiry"] - (now + duration)) <= 3, "expiry now + duration")
    else:
        check(r["expiry"] == expiry, "expiry %d (got %d)" % (expiry, r["expiry"]))
    check(abs(r["session"] - (r["expiry"] - now)) <= 3, "session is the remaining time")
    check(r["wlan"] == 7, "WLAN id echoed")
    check(r["macs"][0] == mac_bytes(mac), "the requesting MAC first in the list")
    if macs is not None:
        check([m.hex(":") for m in r["macs"]] == macs, "MAC list %r (got %r)" % (macs, [m.hex(":") for m in r["macs"]]))
    check(r["pass"] == passwd[:LAYOUTS[layout]["pass_len"] - 1], "pass echoed")
    check(r["uuid"] == uuid_, "uuid")
    check(r["name"] == name, "name %r (got %r)" % (name, r["name"]))


def test_local(layout, status_kind):
    print("guestd: answering itself, %s layout, %s status" % (layout, status_kind))
    g = Guestd(fresh_dir(), layout=layout, status_kind=status_kind, connected=False)
    p = g.passes
    now = int(time.time())
    good = p.add("12345-67890", max_devices=2, name="Room 12 été")
    single = p.add("1111122222", max_devices=1)
    expired_used = p.add("2222233333", first_used=now - 7200, duration=3600)
    expired_unused = p.add("3333344444", redeem_by=now - 10)
    revoked = p.add("4444455555", state=0)
    used = p.add("5555566666", first_used=now - 100, duration=3600, macs=["02:00:00:00:00:aa"])
    try:
        if not g.start():
            return
        m1, m2, m3 = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
        r, addr = g.ask(1, m1, "12345-67890")
        check_ok_reply(r, m1, good, 1, "12345-67890", layout, macs=[m1], name="Room 12 été")
        check(addr == g.idm_path + ".rmc", "the local answer comes from the relay's socket (%r)" % addr)
        if r:
            check(r["maxdev"] == 2, "Max-Devices 2")
        data, _, _ = g.idm.recv(0.2)
        check(data is None, "idm is not asked while disconnected")
        b = g.bindings_lines()
        check(len(b) == 1 and b[0][1:] == [good, m1, "first"], "bindings line 'first' (%r)" % b)
        expiry = r["expiry"] if r else 0

        r, _ = g.ask(2, m2, "1234567890")
        check_ok_reply(r, m2, good, 2, "1234567890", layout, macs=[m2, m1], name="Room 12 été", expiry=expiry)
        b = g.bindings_lines()
        check(len(b) == 2 and b[1][1:] == [good, m2, "device"], "bindings line 'device' (%r)" % b)

        r, _ = g.ask(3, m3, "12345 67890")
        check(r is not None and r["code"] == 485 and r["status"] == 0, "over the device limit: 485")
        r, _ = g.ask(4, m1, "1234567890")
        check(r is not None and r["code"] == 206, "a known device again: 206")
        check(len(g.bindings_lines()) == 2, "no line for a known device")

        r, _ = g.ask(5, m1, "1111122222")
        check(r is not None and r["code"] == 206 and r["maxdev"] == 1 and r["nmacs"] == 1, "single-device pass")

        r, _ = g.ask(6, m1, "2222233333")
        check(r is not None and r["code"] == 490, "used and expired: 490")
        r, _ = g.ask(7, m1, "3333344444")
        check(r is not None and r["code"] == 490, "unused past redeem-by: 490")
        r, _ = g.ask(8, m2, "4444455555")
        check(r is not None and r["code"] == 495, "revoked: 495")
        r, _ = g.ask(9, m2, "9999999999")
        check(r is not None and r["code"] == 480, "unknown: 480")
        r, _ = g.ask(10, m2, "12345")
        check(r is not None and r["code"] == 480, "not a code: 480")
        r, _ = g.ask(11, m3, "5555566666")
        check_ok_reply(r, m3, used, 11, "5555566666", layout, macs=[m3, "02:00:00:00:00:aa"], expiry=now - 100 + 3600)
        b = g.bindings_lines()
        check(b[-1][1:] == [used, m3, "device"], "a new device on a used pass is 'device'")
        _ = (expired_used, expired_unused, revoked, single)
    finally:
        g.close()


def test_reasons():
    print("guestd: 9081 refusing, idm not answering, duplicates, late replies")
    g = Guestd(fresh_dir(), connected=True, portal=False)
    code = "6666677777"
    u = g.passes.add(code)
    try:
        if not g.start():
            return
        r, _ = g.ask(1, "02:00:00:00:01:01", code)
        check(r is not None and r["code"] == 206, "9081 refusing: answered locally")
        data, _, _ = g.idm.recv(0.2)
        check(data is None, "idm is not asked while 9081 refuses")

        g.set_portal(True)
        mac = "02:00:00:00:01:02"
        req = request(50, mac, code, g.layout)
        t0 = time.time()
        g.authd.send(g.idm_path, req)
        g.authd.send(g.idm_path, req)      # a duplicate while the first waits
        data, addr, _ = g.idm.recv()
        check(data == req, "the request reaches idm")
        data2, _, _ = g.idm.recv(0.3)
        check(data2 is None, "the duplicate does not")
        data, _, _ = g.authd.recv(5)
        took = time.time() - t0
        r = parse_reply(data, g.layout) if data else None
        check(r is not None and r["code"] == 206 and r["uuid"] == u, "no reply from idm: answered locally")
        check(2.5 <= took <= 3.0 * SLOW + 1.5, "after about 3 s (%.1f s)" % took)
        late = bytearray(REPLY_LEN)
        struct.pack_into(E + "IIII", late, 0, 3, 6, 50, REPLY_LEN - 0x10)
        late[0x10:0x16] = mac_bytes(mac)
        struct.pack_into(E + "I", late, 0x18, 480)
        g.idm.send(addr, bytes(late))
        data, _, _ = g.authd.recv(0.5)
        check(data is None, "idm's late reply is dropped")
        g.authd.send(g.idm_path, req)
        data, _, _ = g.idm.recv(0.3)
        check(data is None, "a repeat of an answered request is dropped")
    finally:
        g.close()


def test_clock_and_limits():
    print("guestd: clock rule and brute-force limits")
    g = Guestd(fresh_dir(), connected=False, passes=None)
    g.passes.generated = int(time.time()) + 3600
    g.passes.add("7777788888")
    try:
        if not g.start():
            return
        r, _ = g.ask(1, "02:00:00:00:02:01", "7777788888")
        check(r is not None and r["code"] == 480, "a clock before the list's time refuses a good pass")
        check("clock" in g.log_text(), "the log says why")
    finally:
        g.close()

    g = Guestd(fresh_dir(), connected=False)
    g.passes.add("8888899999")
    try:
        if not g.start():
            return
        mac = "02:00:00:00:03:01"
        for i in range(10):
            g.ask(100 + i, mac, "0000000000")
        r, _ = g.ask(200, mac, "8888899999")
        check(r is not None and r["code"] == 480, "the 11th attempt in 300 s is invalid even with a good pass")
        r, _ = g.ask(201, "02:00:00:00:03:02", "8888899999")
        check(r is not None and r["code"] == 206, "another device is not limited")
        codes = []
        for i in range(25):
            r, _ = g.ask(300 + i, "02:00:00:00:04:%02x" % i, "0000000000")
            codes.append(r["code"] if r else None)
        check(codes.count(401) >= 5 and codes[0] == 480, "more than 30 a minute per AP are refused with 401 (%r)" % codes)
    finally:
        g.close()


def test_restart_reload_shutdown():
    print("guestd: idm restart, reload, malformed input, shutdown, recovery")
    g = Guestd(fresh_dir(), connected=False)
    code = "1212134343"
    u = g.passes.add(code, max_devices=3)
    try:
        if not g.start():
            return
        ours = os.stat(g.idm_path).st_ino

        # malformed datagrams: nothing crashes, the relay still works
        for junk in [b"", b"\x01", b"\x05\0\0\0", struct.pack(E + "II", 3, 5) + b"x" * 10, os.urandom(2000),
                     struct.pack(E + "IIII", 3, 5, 1, 0) + b"\xff" * (REQ_LEN - 16), os.urandom(REQ_LEN)]:
            g.authd.send(g.idm_path, junk)
        try:
            g.authd.send(g.idm_path, b"z" * 0x10800)
        except OSError:
            pass
        time.sleep(0.5)
        g.authd.drain()
        check(g.proc.poll() is None, "still running after malformed datagrams")

        r, _ = g.ask(1, "02:00:00:00:05:01", code)
        check(r is not None and r["code"] == 206, "answers after malformed datagrams")
        first_expiry = r["expiry"] if r else 0

        # idm restarts: unlinks /var/run/idm, binds a new socket
        g.idm.close()
        os.unlink(g.idm_path)
        g.idm = Dgram(g.idm_path)
        g.idm_ino = os.stat(g.idm_path).st_ino
        check(wait_for(lambda: g.taken(), 4), "takes over again after idm restarts")
        check(os.stat(g.idm_path).st_ino != ours, "with a new socket")
        g.set_connected(True)
        g.authd.send(g.idm_path, struct.pack(E + "IIII", 3, 3, 9, 0))
        data, _, _ = g.idm.recv()
        check(data is not None, "relays to the new idm")
        g.set_connected(False)

        # reload: a new list (without the first use) keeps the binding from the bindings file
        g.passes.records.clear()
        h = hashlib.sha256(g.passes.salt + code.encode()).hexdigest()
        g.passes.records.append("%s %s 1 - - 3600 3 - -" % (h, u))
        new = g.passes.add("5656578787")
        g.passes.write()
        g.proc.send_signal(signal.SIGHUP)
        time.sleep(0.6 * SLOW)
        r, _ = g.ask(2, "02:00:00:00:05:02", "5656578787")
        check(r is not None and r["code"] == 206 and r["uuid"] == new, "a pass added by a reload works")
        r, _ = g.ask(3, "02:00:00:00:05:03", code)
        check(r is not None and r["code"] == 206 and r["expiry"] == first_expiry,
              "the offline first use survives a reload (expiry %r vs %r)" % (r and r["expiry"], first_expiry))
        check(r is not None and r["nmacs"] == 2, "and its device")

        # the controller replaces the list without a signal: the change is picked up by itself
        later = g.passes.add("9090912121")
        g.passes.write()
        time.sleep(1.5 * SLOW)
        r, _ = g.ask(4, "02:00:00:00:05:04", "9090912121")
        check(r is not None and r["code"] == 206 and r["uuid"] == later, "a replaced list is reloaded without SIGHUP")

        # the controller collects the bindings by renaming the file away; the next line starts a new file
        os.rename(g.bindings, g.bindings + ".taken")
        r, _ = g.ask(5, "02:00:00:00:05:05", "9090912121")
        lines = g.bindings_lines()
        check(len(lines) == 1 and lines[0][1:] == [later, "02:00:00:00:05:05", "device"],
              "after the file is renamed away the next line goes to a new file (%r)" % lines)
        check(g.proc.poll() is None, "guestd stays in the foreground (the started process is the daemon)")

        # shutdown restores idm's name
        g.stop()
        check(g.proc.returncode == 0, "exit status 0")
        check(os.stat(g.idm_path).st_ino == g.idm_ino, "SIGTERM gives /var/run/idm back to idm")
        check(not os.path.exists(g.idm_path + ".real"), "idm.real is gone")
        check(not [f for f in os.listdir(g.d) if ".rmc" in f and not f.endswith(".lock")], "relay sockets are gone")

        # a relay killed outright: the next one gives the name back first and takes over again
        g.start()
        g.proc.kill()
        g.proc.wait()
        check(os.stat(g.idm_path).st_ino != g.idm_ino, "after SIGKILL the dead relay's socket has the name")
        g.start()
        check(g.taken(), "a new relay recovers and takes over")
        g.set_connected(True)
        g.authd.send(g.idm_path, struct.pack(E + "IIII", 3, 3, 10, 0))
        data, _, _ = g.idm.recv()
        check(data is not None, "and relays to idm")
    finally:
        g.close()


def test_args():
    print("guestd/portal: argument errors")
    for args in [["guestd"], ["guestd", "--layout", "middle"], ["portal", "--address", "x"], ["portal", "--passes"]]:
        rc = subprocess.run(CMD + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        check(rc == 2, "%r exits 2 (got %d)" % (args, rc))


# ---- portal -------------------------------------------------------------------------------------------------------

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http(port, raw, src="127.0.0.1"):
    s = socket.socket()
    s.bind((src, 0))
    s.settimeout(5 * SLOW)
    s.connect(("127.0.0.1", port))
    s.sendall(raw)
    out = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    s.close()
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status = lines[0] if lines else ""
    headers = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers, body.decode(errors="replace")


class Hostapd:
    """Stand-in hostapd control sockets: each answers its own reply and records the commands it gets."""

    def __init__(self, d, replies):
        self.dir = os.path.join(d, "hostapd")
        os.makedirs(self.dir, exist_ok=True)
        self.socks = {}
        self.got = {}
        for name, reply in replies.items():
            self.socks[name] = (Dgram(os.path.join(self.dir, name)), reply)
            self.got[name] = []

    def pump(self, seconds=0.0):
        end = time.time() + seconds
        while True:
            for name, (sock, reply) in self.socks.items():
                sock.s.setblocking(False)
                try:
                    data, addr = sock.s.recvfrom(4096)
                except BlockingIOError:
                    continue
                self.got[name].append(data.decode())
                if reply is not None:
                    sock.s.sendto(reply, addr)
            if time.time() >= end:
                return
            time.sleep(0.01)


def post_async(port, path, body, src="127.0.0.1"):
    """Posts in a thread so the test can play hostapd meanwhile."""
    import threading
    result = {}

    def run():
        raw = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
               "Content-Length: %d\r\n\r\n%s" % (path, len(body), body)).encode()
        result["r"] = http(port, raw, src)

    t = threading.Thread(target=run)
    t.start()
    return t, result


def run_post(hostapd, port, path, body, src="127.0.0.1"):
    t, result = post_async(port, path, body, src)
    while t.is_alive():
        hostapd.pump(0.05)
    return result.get("r", ("", {}, ""))


def test_portal(terms=False):
    print("portal: %s" % ("terms" if terms else "guest passes"))
    d = fresh_dir()
    p1, p2 = free_port(), free_port()
    hostapd = Hostapd(d, {"wlan0": b"FAIL\n", "wlan1": b"OK\n"})
    passes = Passes(os.path.join(d, "guests"))
    good = passes.add("1357924680", max_devices=1, duration=1800)
    passes.write()
    bindings = os.path.join(d, "guest-bindings")
    env = dict(os.environ, RMC_PORTAL_PORTS="%d,%d" % (p1, p2), RMC_PORTAL_HOSTAPD=hostapd.dir)
    args = ["portal", "--passes", passes.path, "--bindings", bindings, "--address", "10.1.2.3",
            "--log", os.path.join(d, "portal.log")] + (["--terms"] if terms else [])
    proc = subprocess.Popen(CMD + args, env=env)
    try:
        def up():
            try:
                socket.create_connection(("127.0.0.1", p2), 0.2).close()
                return True
            except OSError:
                return False
        check(wait_for(up, 5), "portal listens")
        mac = "02:00:00:00:09:01"
        st, h, body = http(p1, ("GET /generate_204 HTTP/1.1\r\nHost: example.com\r\nclient_mac: %s\r\nuip: 127.0.0.1\r\n"
                                "\r\n" % mac).encode())
        check(st.startswith("HTTP/1.1 302"), "8090 redirects (%s)" % st)
        loc = h.get("location", "")
        check(loc.startswith("http://10.1.2.3:%d/login?t=" % p2), "to the form on the AP's address (%s)" % loc)
        ticket = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("t", [""])[0]
        check(ticket.startswith(mac.replace(":", "")), "the ticket names the client MAC")

        st, h, body = http(p1, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        check("could not be identified" in body, "no client_mac and no ARP entry: no ticket")

        st, h, body = http(p2, ("GET /login?t=%s HTTP/1.1\r\nHost: x\r\n\r\n" % ticket).encode())
        check(st.startswith("HTTP/1.1 200") and ticket in body and "<form" in body, "the form carries the ticket")

        st, h, body = http(p2, ("GET /login?t=%s HTTP/1.1\r\nHost: x\r\n\r\n" % ticket.replace("0", "1", 1)).encode())
        check("<form" not in body, "a changed ticket gets no form")

        if terms:
            st, h, body = run_post(hostapd, p2, "/login", "t=%s&accept=1" % ticket)
            check("You are connected" in body, "accepting the terms connects")
            check(hostapd.got["wlan1"] == ["AUTH mac %s proxy 0 u:guest" % mac], "hostapd got %r" % hostapd.got)
            check(not os.path.exists(bindings), "terms leave no bindings line")
            return

        st, h, body = run_post(hostapd, p2, "/login", "t=%s&code=1111111111" % ticket)
        check("not valid" in body and "<form" in body, "a bad pass shows the form again")
        check(hostapd.got["wlan0"] == [] and hostapd.got["wlan1"] == [], "and sends hostapd nothing")

        st, h, body = run_post(hostapd, p2, "/login", "t=%s&code=13579-24680" % ticket, src="127.0.0.2")
        check("expired" in body, "a ticket posted from another address is refused")

        st, h, body = run_post(hostapd, p2, "/login", "t=%s&code=13579-24680" % ticket)
        check("You are connected" in body, "a good pass connects (%s)" % body[-120:])
        sent = hostapd.got["wlan0"] + hostapd.got["wlan1"]
        check(len(hostapd.got["wlan1"]) == 1, "hostapd wlan1 said OK")
        if hostapd.got["wlan1"]:
            cmd = hostapd.got["wlan1"][0].split()
            check(cmd[:5] == ["AUTH", "mac", mac, "proxy", "0"] and cmd[5] == "u:" + good and cmd[7] == "uk:" + good,
                  "AUTH line %r" % cmd)
            check(1790 <= int(cmd[6][2:]) <= 1800, "s: is the remaining time")
        _ = sent
        with open(bindings) as f:
            lines = [l.split() for l in f.read().splitlines()]
        check(len(lines) == 1 and lines[0][1:] == [good, mac, "first"], "bindings line 'first' (%r)" % lines)

        # a second device on a one-device pass
        mac2 = "02:00:00:00:09:02"
        st, h, body = http(p1, ("GET / HTTP/1.1\r\nclient_mac: %s\r\n\r\n" % mac2.upper()).encode())
        t2 = urllib.parse.parse_qs(urllib.parse.urlparse(h.get("location", "")).query).get("t", [""])[0]
        st, h, body = run_post(hostapd, p2, "/login", "t=%s&code=1357924680" % t2)
        check("as many devices" in body, "a second device on a one-device pass is refused")

        # hostapd refusing everywhere: no binding is recorded
        hostapd.socks["wlan1"] = (hostapd.socks["wlan1"][0], b"FAIL\n")
        passes.add("2468013579")
        passes.write()
        time.sleep(1.2 * SLOW)
        st, h, body = run_post(hostapd, p2, "/login", "t=%s&code=2468013579" % t2)
        check("Connecting failed" in body, "no hostapd says OK: the guest is told")
        with open(bindings) as f:
            check(len(f.read().splitlines()) == 1, "and nothing is recorded")

        # malformed requests
        for raw in [b"\x00\x01\x02\r\n\r\n", b"GARBAGE\r\n\r\n", b"GET " + b"a" * 5000 + b" HTTP/1.1\r\n\r\n",
                    b"POST /login HTTP/1.1\r\nContent-Length: 99999\r\n\r\n", b"GET /nothing HTTP/1.1\r\n\r\n"]:
            try:
                http(p2, raw)
            except OSError:
                pass
        s = socket.create_connection(("127.0.0.1", p2))
        s.close()
        check(proc.poll() is None, "still running after malformed requests")
        st, h, body = http(p2, ("GET /login?t=%s HTTP/1.1\r\n\r\n" % t2).encode())
        check("<form" in body, "and still answering")
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(5 * SLOW)
            check(proc.returncode == 0, "portal exits 0 on SIGTERM")
        except subprocess.TimeoutExpired:
            proc.kill()
            check(False, "portal stops on SIGTERM")


def main():
    print("running", " ".join(CMD), "(byte order %s)" % {"<": "little", ">": "big", "=": "native"}[E])
    test_args()
    test_relay()
    test_local("long", "int")
    test_local("short", "run")
    test_reasons()
    test_clock_and_limits()
    test_restart_reload_shutdown()
    test_portal()
    test_portal(terms=True)
    print("%d checks passed, %d failed" % (passed, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
