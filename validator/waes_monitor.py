"""WAES-256 counter-mode hardware validation monitor.

Receives the UDP test packets sent by waes_ctr_test (FPGA 192.168.1.50,
UDP port 17767), validates every record against the reference model and
shows live statistics.

Processes (no shared interpreter lock, so receiving is never blocked):
  receiver process  : socket -> batches of packets -> batch queue. It only
                      receives; packet loss is counted here, exactly, from the
                      sequence numbers. If validation falls behind, batches
                      are dropped and counted as "not validated" instead of
                      blocking the socket.
  validator workers : batch queue -> waes_validator.validate_batch -> results
  GUI (main)        : collects results and statistics, refreshes the display

Save report stops receiving, waits until every received packet has been
validated, and then writes the JSON and TXT reports.

The PC must own 192.168.1.100 on the interface connected to the board (the
FPGA sends to that address and resolves its MAC with ARP).

  python waes_monitor.py
"""

import json
import multiprocessing as mp
import os
import queue
import socket
import sys
import time
import tkinter as tk
from tkinter import filedialog, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import waes_validator as wv  # noqa: E402

DEFAULT_FPGA_IP = "192.168.1.50"
DEFAULT_PORT = 17767
BIND_ADDR = ""                    # all local interfaces
RCVBUF_BYTES = 256 * 1024 * 1024  # requested socket receive buffer
BATCH_PACKETS = 512
BATCH_TIMEOUT_S = 0.05
MAX_PENDING_BATCHES = 2000        # batches waiting for validation (~1M packets)
STATUS_PERIOD_S = 0.25
MAX_DEFAULT_WORKERS = 4           # ~1 M blocks/s; more only starves the receiver


def set_priority(level):
    """Windows process priority: 'high' for the receiver, 'low' for validators."""
    if sys.platform != "win32":
        return
    import ctypes
    cls = {"high": 0x00000080, "low": 0x00004000}[level]   # HIGH / BELOW_NORMAL
    k32 = ctypes.windll.kernel32
    k32.SetPriorityClass(k32.GetCurrentProcess(), cls)


# --------------------------------------------------------------------------- #
# Receiver process
# --------------------------------------------------------------------------- #
def receiver_proc(bind_addr, port, fpga_ip, batch_q, status_q, stop_evt):
    set_priority("high")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
    try:
        sock.bind((bind_addr, port))
    except OSError as e:
        status_q.put(("error", f"socket bind failed: {e}"))
        status_q.put(("rx_done", None))
        return
    sock.settimeout(0.05)
    rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)

    st = {"rx_packets": 0, "rx_bytes": 0, "lost": 0, "reordered": 0,
          "foreign": 0, "batches_sent": 0, "batch_drops": 0,
          "packets_not_validated": 0, "seq_first": None, "seq_last": None,
          "rcvbuf": rcvbuf}
    expected = None
    batch, t_batch, t_status = [], time.time(), 0.0
    buf = bytearray(2048)

    def flush():
        nonlocal batch, t_batch
        if batch:
            try:
                batch_q.put_nowait(batch)
                st["batches_sent"] += 1
            except queue.Full:
                st["batch_drops"] += 1
                st["packets_not_validated"] += len(batch)
            batch = []
        t_batch = time.time()

    while not stop_evt.is_set():
        try:
            n, addr = sock.recvfrom_into(buf)
        except (socket.timeout, OSError):
            n = 0
        if n:
            if addr[0] != fpga_ip:
                st["foreign"] += 1
            else:
                pkt = bytes(buf[:n])
                st["rx_packets"] += 1
                st["rx_bytes"] += n
                if n >= 12 and pkt[:4] == wv.MAGIC:
                    seq = int.from_bytes(pkt[8:12], "big")
                    if expected is None:
                        st["seq_first"] = seq
                    elif seq > expected:
                        st["lost"] += seq - expected          # gap = never received
                    elif seq < expected:
                        st["reordered"] += 1                  # late or duplicate
                    if expected is None or seq >= expected:
                        expected = seq + 1
                        st["seq_last"] = seq
                batch.append(pkt)
                if len(batch) >= BATCH_PACKETS:
                    flush()
        now = time.time()
        if batch and now - t_batch >= BATCH_TIMEOUT_S:
            flush()
        if now - t_status >= STATUS_PERIOD_S:
            status_q.put(("rx", dict(st)))
            t_status = now
    flush()
    sock.close()
    status_q.put(("rx", dict(st)))
    status_q.put(("rx_done", None))


# --------------------------------------------------------------------------- #
# Validator worker process
# --------------------------------------------------------------------------- #
def validator_proc(batch_q, result_q):
    set_priority("low")
    while True:
        batch = batch_q.get()
        if batch is None:
            break
        try:
            res = wv.validate_batch(batch)
        except Exception as e:  # noqa: BLE001
            res = wv.new_stats()
            res["errors"].append(("internal", None, None, repr(e)))
        result_q.put(res)


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
EMPTY_RX = {"rx_packets": 0, "rx_bytes": 0, "lost": 0, "reordered": 0,
            "foreign": 0, "batches_sent": 0, "batch_drops": 0,
            "packets_not_validated": 0, "seq_first": None, "seq_last": None,
            "rcvbuf": 0}


class Monitor:
    def __init__(self, root):
        self.root = root
        root.title("WAES-256 CTR hardware validation")
        self.running = False      # processes alive
        self.receiving = False    # receiver active
        self.rx_done = False
        self.save_path = None
        self.fpga_ip = DEFAULT_FPGA_IP
        self._build_ui()
        self._reset_stats()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(250, self.refresh)

    # ------------------------------------------------------------------ state
    def _reset_stats(self):
        self.stats = wv.new_stats()
        self.rx = dict(EMPTY_RX)
        self.batches_done = 0
        self.t_start = time.time()
        self.t_stop = None
        self.rate_mark = (self.t_start, 0, 0)
        self.rate_txt = ("0.0", "0")
        self.n_logged = 0
        self.log.delete("1.0", "end")

    # --------------------------------------------------------------------- UI
    def _build_ui(self):
        cfg = ttk.LabelFrame(self.root, text="Connection")
        cfg.pack(fill="x", padx=8, pady=4)
        self.ip_var = tk.StringVar(value=DEFAULT_FPGA_IP)
        self.port_var = tk.IntVar(value=DEFAULT_PORT)
        self.workers_var = tk.IntVar(value=max(1, min(MAX_DEFAULT_WORKERS, (os.cpu_count() or 3) - 2)))
        for col, (lbl, var, w) in enumerate((("FPGA IP", self.ip_var, 14),
                                             ("UDP port", self.port_var, 7),
                                             ("validator processes", self.workers_var, 4))):
            ttk.Label(cfg, text=lbl).grid(row=0, column=2 * col, padx=4, pady=4, sticky="e")
            ttk.Entry(cfg, textvariable=var, width=w).grid(row=0, column=2 * col + 1, padx=4)
        self.btn_start = ttk.Button(cfg, text="Start", command=self.start)
        self.btn_start.grid(row=0, column=6, padx=4)
        self.btn_stop = ttk.Button(cfg, text="Stop", command=self.stop, state="disabled")
        self.btn_stop.grid(row=0, column=7, padx=4)
        ttk.Button(cfg, text="Reset statistics", command=self.reset).grid(row=0, column=8, padx=4)
        ttk.Button(cfg, text="Save report", command=self.save_report).grid(row=0, column=9, padx=4)

        self.status_var = tk.StringVar(value="Stopped")
        ttk.Label(self.root, textvariable=self.status_var,
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10)

        grid = ttk.LabelFrame(self.root, text="Statistics")
        grid.pack(fill="x", padx=8, pady=4)
        self.fields = {}
        rows = [
            ("elapsed", "Elapsed time"), ("rx_packets", "Packets received"),
            ("rate", "Receive rate"), ("lost", "Packets lost (sequence gaps)"),
            ("reordered", "Packets late / duplicate"),
            ("backlog", "Validation pending / not validated"),
            ("validated", "Packets validated"), ("records", "Records (blocks) verified"),
            ("bytes", "Plaintext bytes compared"), ("sessions", "Sessions / keys / nonces"),
            ("profiles", "Records per stall profile 0/25/50/75 %"), ("format", "Format errors"),
            ("cipher", "Ciphertext mismatches"), ("roundtrip", "Plaintext/decrypted mismatches"),
            ("counter", "Counter-rule violations"), ("rcvbuf", "Socket receive buffer"),
        ]
        for i, (key, label) in enumerate(rows):
            ttk.Label(grid, text=label + ":").grid(row=i // 2, column=2 * (i % 2),
                                                   sticky="e", padx=6, pady=2)
            var = tk.StringVar(value="0")
            ttk.Label(grid, textvariable=var, width=34, font=("Consolas", 10)).grid(
                row=i // 2, column=2 * (i % 2) + 1, sticky="w")
            self.fields[key] = var

        log = ttk.LabelFrame(self.root, text="Error samples")
        log.pack(fill="both", expand=True, padx=8, pady=4)
        self.log = tk.Text(log, height=10, font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)

    # ---------------------------------------------------------------- control
    def start(self):
        if self.running:
            return
        self._reset_stats()
        self.fpga_ip = self.ip_var.get().strip()
        n_workers = max(1, int(self.workers_var.get()))
        self.batch_q = mp.Queue(maxsize=MAX_PENDING_BATCHES)
        self.result_q = mp.Queue()
        self.status_q = mp.Queue()
        self.stop_evt = mp.Event()
        self.workers = [mp.Process(target=validator_proc, args=(self.batch_q, self.result_q),
                                   daemon=True) for _ in range(n_workers)]
        for w in self.workers:
            w.start()
        self.receiver = mp.Process(target=receiver_proc, daemon=True,
                                   args=(BIND_ADDR, int(self.port_var.get()), self.fpga_ip,
                                         self.batch_q, self.status_q, self.stop_evt))
        self.receiver.start()
        self.running = True
        self.receiving = True
        self.rx_done = False
        self.t_start = time.time()
        self.rate_mark = (self.t_start, 0, 0)
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status_var.set(f"Receiving from {self.fpga_ip}:{self.port_var.get()} ...")

    def stop(self):
        """Stop receiving; validation of everything already received continues."""
        if not self.receiving:
            return
        self.stop_evt.set()
        self.receiving = False
        self.t_stop = time.time()
        self.btn_stop.config(state="disabled")
        self.status_var.set("Stopping: finishing validation of received packets ...")

    def reset(self):
        if self.running:
            self.status_var.set("Stop the test before resetting statistics.")
            return
        self._reset_stats()
        self.status_var.set("Statistics reset.")

    def _finish(self):
        """Receiver is done and every batch has been validated."""
        for _ in self.workers:
            self.batch_q.put(None)
        for w in self.workers:
            w.join(timeout=2)
        self.receiver.join(timeout=2)
        self.running = False
        self.btn_start.config(state="normal")
        st = self.stats
        n_err = st["format_err"] + st["cipher_err"] + st["roundtrip_err"] + st["counter_err"]
        self.status_var.set("Stopped. All received packets validated: "
                            + ("ERRORS DETECTED" if n_err else "no mismatches"))
        if self.save_path:
            self._write_report(self.save_path)
            self.save_path = None

    def on_close(self):
        if self.running:
            self.stop_evt.set()
            for w in self.workers:
                w.terminate()
            self.receiver.terminate()
        self.root.destroy()

    # ---------------------------------------------------------------- display
    def _pending_batches(self):
        return max(self.rx["batches_sent"] - self.batches_done, 0)

    def refresh(self):
        if self.running:
            try:
                while True:
                    kind, val = self.status_q.get_nowait()
                    if kind == "rx":
                        self.rx = val
                    elif kind == "rx_done":
                        self.rx_done = True
                    elif kind == "error":
                        self.status_var.set(val)
                        self.stop()
            except queue.Empty:
                pass
            try:
                while True:
                    wv.merge_stats(self.stats, self.result_q.get_nowait())
                    self.batches_done += 1
            except queue.Empty:
                pass
            if not self.receiving and self.rx_done and self._pending_batches() == 0:
                self.rx_done = False
                self._finish()

        st, rx = self.stats, self.rx
        now = time.time() if self.t_stop is None else self.t_stop
        t0, p0, b0 = self.rate_mark
        if self.receiving and now - t0 >= 1.0:
            mbps = (rx["rx_bytes"] - b0) * 8 / (now - t0) / 1e6
            pps = (rx["rx_packets"] - p0) / (now - t0)
            self.rate_txt = (f"{mbps:.1f}", f"{pps:.0f}")
            self.rate_mark = (now, rx["rx_packets"], rx["rx_bytes"])
        n_err = st["format_err"] + st["cipher_err"] + st["roundtrip_err"] + st["counter_err"]
        span = 0 if rx["seq_first"] is None else rx["seq_last"] - rx["seq_first"] + 1
        loss_pct = 100.0 * rx["lost"] / span if span else 0.0
        f = self.fields
        f["elapsed"].set(time.strftime("%H:%M:%S", time.gmtime(now - self.t_start)))
        f["rx_packets"].set(f"{rx['rx_packets']}")
        f["rate"].set(f"{self.rate_txt[0]} Mb/s payload, {self.rate_txt[1]} pkt/s")
        f["lost"].set(f"{rx['lost']}  ({loss_pct:.3f} %)")
        f["reordered"].set(f"{rx['reordered']}")
        f["backlog"].set(f"{self._pending_batches()} batches / {rx['packets_not_validated']} pkts")
        f["validated"].set(f"{st['packets']}")
        f["records"].set(f"{st['records']}")
        f["bytes"].set(f"{st['records'] * 32}")
        f["sessions"].set(f"{len(st['sessions'])} / {len(st['keys'])} / {len(st['nonces'])}")
        f["profiles"].set(" / ".join(str(x) for x in st["profile_records"]))
        f["format"].set(f"{st['format_err']}")
        f["cipher"].set(f"{st['cipher_err']}")
        f["roundtrip"].set(f"{st['roundtrip_err']}")
        f["counter"].set(f"{st['counter_err']}")
        f["rcvbuf"].set(f"{rx['rcvbuf'] // (1024 * 1024)} MB" if rx["rcvbuf"] else "-")
        for e in st["errors"][self.n_logged:]:
            self.log.insert("end", f"{e}\n")
        self.n_logged = len(st["errors"])
        if self.receiving:
            state = "ERRORS DETECTED" if n_err else "OK - no mismatches"
            self.status_var.set(f"Receiving from {self.fpga_ip}  |  {state}")
        self.root.after(250, self.refresh)

    # ----------------------------------------------------------------- report
    def save_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")],
                                            initialfile="waes_ctr_validation_report.json")
        if not path:
            return
        if self.running:
            # stop receiving, finish validation, then write the report (_finish)
            self.save_path = path
            self.stop()
            self.status_var.set("Stopping and finishing validation before saving ...")
        else:
            self._write_report(path)

    def _write_report(self, path):
        st, rx = self.stats, self.rx
        span = 0 if rx["seq_first"] is None else rx["seq_last"] - rx["seq_first"] + 1
        t_end = self.t_stop if self.t_stop is not None else time.time()
        rep = {
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_s": round(t_end - self.t_start, 1),
            "fpga_ip": self.ip_var.get(), "udp_port": int(self.port_var.get()),
            "packets_sent_by_fpga_in_span": span,
            "packets_received": rx["rx_packets"],
            "packets_lost_seq_gaps": rx["lost"],
            "packets_late_or_duplicate": rx["reordered"],
            "packets_not_validated_backlog": rx["packets_not_validated"],
            "packets_validated": st["packets"],
            "records_verified": st["records"],
            "plaintext_bytes_compared": st["records"] * 32,
            "sessions": len(st["sessions"]), "keys": len(st["keys"]),
            "nonces": len(st["nonces"]),
            "records_per_stall_profile_0_25_50_75": st["profile_records"],
            "format_errors": st["format_err"],
            "ciphertext_mismatches": st["cipher_err"],
            "plaintext_decrypted_mismatches": st["roundtrip_err"],
            "counter_rule_violations": st["counter_err"],
            "socket_receive_buffer_bytes": rx["rcvbuf"],
            "error_samples": [list(map(str, e)) for e in st["errors"]],
        }
        with open(path, "w") as fh:
            json.dump(rep, fh, indent=2)
        lines = [
            f"duration                : {rep['duration_s']} s",
            f"packets sent (seq span) : {span}",
            f"packets received        : {rx['rx_packets']}",
            f"packets lost (seq gaps) : {rx['lost']}",
            f"packets late/duplicate  : {rx['reordered']}",
            f"packets not validated   : {rx['packets_not_validated']}",
            f"packets validated       : {st['packets']}",
            f"records verified        : {st['records']}  ({st['records'] * 32} plaintext bytes)",
            f"sessions / keys / nonces: {len(st['sessions'])} / {len(st['keys'])} / {len(st['nonces'])}",
            "records per stall profile (0/25/50/75 %): "
            + " / ".join(str(x) for x in st["profile_records"]),
            f"format errors           : {st['format_err']}",
            f"cipher mismatches       : {st['cipher_err']}",
            f"plaintext/decrypted mismatches: {st['roundtrip_err']}",
            f"counter-rule violations : {st['counter_err']}",
        ]
        with open(os.path.splitext(path)[0] + ".txt", "w") as fh:
            fh.write("\n".join(lines) + "\n")
        self.status_var.set(f"Report saved to {path}")


def main():
    mp.freeze_support()
    root = tk.Tk()
    Monitor(root)
    root.mainloop()


if __name__ == "__main__":
    main()
