import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import nmap
import threading
import datetime
import socket
import math

# ─────────────────────────────────────────────
#  COLOR THEME  —  Clean White & Grey (Minimal)
# ─────────────────────────────────────────────
BG_MAIN    = "#f5f5f5"
BG_PANEL   = "#ffffff"
BG_ENTRY   = "#f0f0f0"
BG_RESULT  = "#fafafa"
BG_HEADER  = "#e8e8e8"

ACCENT     = "#222222"
ACCENT_DIM = "#444444"

TEXT_PRI   = "#1a1a1a"
TEXT_SEC   = "#666666"
TEXT_DIM   = "#aaaaaa"

COL_OPEN     = "#1a7a3a"
COL_CLOSED   = "#c0392b"
COL_FILTERED = "#b07d00"
COL_INFO     = "#1a4a7a"
COL_OS       = "#5a3a8a"
COL_SEP      = "#dddddd"

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 119: "NNTP",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    194: "IRC", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

def get_service(port):
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return "Unknown"


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Port Scanner")
        self.root.geometry("880x720")
        self.root.resizable(True, True)
        self.root.configure(bg=BG_MAIN)

        self.scan_running  = False
        self.scan_results  = []
        self.start_time    = None

        # animation state
        self._dot_count    = 0
        self._pulse_up     = True
        self._pulse_val    = 0
        self._radar_angle  = 0
        self._dot_job      = None
        self._pulse_job    = None
        self._radar_job    = None
        self._type_queue   = []   # (text, tag) pairs waiting to be typed in
        self._type_job     = None

        self._build_ui()
        self._start_idle_animations()

    # ──────────────────────────────────────────
    #  BUILD UI
    # ──────────────────────────────────────────
    def _build_ui(self):

        # HEADER
        top = tk.Frame(self.root, bg=BG_PANEL, pady=16)
        top.pack(fill="x")

        tk.Label(top, text="Network Port Scanner",
                 font=("Segoe UI", 18, "bold"),
                 bg=BG_PANEL, fg=TEXT_PRI).pack(side="left", padx=28)

        # ── RADAR CANVAS (top-right, idle animation) ──
        self.radar_canvas = tk.Canvas(top, width=52, height=52,
                                      bg=BG_PANEL, highlightthickness=0)
        self.radar_canvas.pack(side="right", padx=28)
        self._draw_radar(0)

        tk.Frame(self.root, bg=COL_SEP, height=1).pack(fill="x")

        # INPUT PANEL
        panel = tk.Frame(self.root, bg=BG_PANEL, padx=28, pady=18)
        panel.pack(fill="x")

        def lbl(parent, text):
            return tk.Label(parent, text=text,
                            font=("Segoe UI", 10),
                            bg=BG_PANEL, fg=TEXT_SEC,
                            width=22, anchor="w")

        def ent(parent, var, w=28):
            return tk.Entry(parent, textvariable=var,
                            font=("Segoe UI", 11),
                            bg=BG_ENTRY, fg=TEXT_PRI,
                            insertbackground=ACCENT,
                            relief="flat",
                            highlightthickness=1,
                            highlightbackground=COL_SEP,
                            highlightcolor=ACCENT,
                            width=w)

        r1 = tk.Frame(panel, bg=BG_PANEL)
        r1.pack(fill="x", pady=(0, 10))
        lbl(r1, "Target IP / Hostname").pack(side="left")
        self.ip_var = tk.StringVar(value="127.0.0.1")
        ent(r1, self.ip_var, 32).pack(side="left", ipady=6)

        r2 = tk.Frame(panel, bg=BG_PANEL)
        r2.pack(fill="x", pady=(0, 10))
        lbl(r2, "Port Range").pack(side="left")
        self.port_start = tk.StringVar(value="1")
        self.port_end   = tk.StringVar(value="1024")
        ent(r2, self.port_start, 7).pack(side="left", ipady=6)
        tk.Label(r2, text="   to   ", font=("Segoe UI", 10),
                 bg=BG_PANEL, fg=TEXT_SEC).pack(side="left")
        ent(r2, self.port_end, 7).pack(side="left", ipady=6)

        r3 = tk.Frame(panel, bg=BG_PANEL)
        r3.pack(fill="x")
        lbl(r3, "Options").pack(side="left")
        self.service_detect = tk.BooleanVar(value=True)
        self.os_detect      = tk.BooleanVar(value=False)

        def chk(parent, text, var):
            return tk.Checkbutton(parent, text=text, variable=var,
                                  font=("Segoe UI", 10),
                                  bg=BG_PANEL, fg=TEXT_PRI,
                                  selectcolor=BG_ENTRY,
                                  activebackground=BG_PANEL,
                                  activeforeground=ACCENT)

        chk(r3, "Service Detection  (-sV)", self.service_detect).pack(side="left", padx=(0, 24))
        chk(r3, "OS Detection  (-O)  [admin required]", self.os_detect).pack(side="left")

        tk.Frame(self.root, bg=COL_SEP, height=1).pack(fill="x")

        # BUTTONS
        bf = tk.Frame(self.root, bg=BG_MAIN, pady=12)
        bf.pack(fill="x", padx=28)

        # scan button — will pulse during scan
        self.scan_btn = tk.Button(
            bf, text="  Start Scan  ",
            command=self.start_scan,
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT, fg="#ffffff",
            activebackground=ACCENT_DIM,
            activeforeground="#ffffff",
            relief="flat", padx=20, pady=8,
            cursor="hand2"
        )
        self.scan_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = tk.Button(
            bf, text="  Stop  ",
            command=self.stop_scan,
            font=("Segoe UI", 10),
            bg=BG_PANEL, fg=COL_CLOSED,
            activebackground=ACCENT_DIM,
            activeforeground="#ffffff",
            relief="flat", padx=20, pady=8,
            cursor="hand2", state="disabled"
        )
        self.stop_btn.pack(side="left", padx=(0, 8))

        tk.Button(
            bf, text="  Save Results  ",
            command=self.save_results,
            font=("Segoe UI", 10),
            bg=BG_PANEL, fg=COL_INFO,
            activebackground=ACCENT_DIM,
            activeforeground="#ffffff",
            relief="flat", padx=20, pady=8,
            cursor="hand2"
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            bf, text="  Clear  ",
            command=self.clear_results,
            font=("Segoe UI", 10),
            bg=BG_PANEL, fg=TEXT_SEC,
            activebackground=ACCENT_DIM,
            activeforeground="#ffffff",
            relief="flat", padx=20, pady=8,
            cursor="hand2"
        ).pack(side="left")

        # STATUS ROW
        sf = tk.Frame(self.root, bg=BG_PANEL, pady=7)
        sf.pack(fill="x")
        tk.Frame(self.root, bg=COL_SEP, height=1).pack(fill="x")

        # animated dot status label
        self.status_var = tk.StringVar(
            value="Ready  -  enter a target and press Start Scan.")
        tk.Label(sf, textvariable=self.status_var,
                 font=("Segoe UI", 10), bg=BG_PANEL,
                 fg=TEXT_SEC, anchor="w").pack(side="left", padx=28)

        self.timer_var = tk.StringVar(value="")
        tk.Label(sf, textvariable=self.timer_var,
                 font=("Segoe UI", 10), bg=BG_PANEL,
                 fg=TEXT_DIM, anchor="e").pack(side="right", padx=28)

        # PROGRESS BAR
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("minimal.Horizontal.TProgressbar",
                        troughcolor=BG_ENTRY, background=ACCENT,
                        darkcolor=ACCENT, lightcolor=ACCENT,
                        bordercolor=BG_PANEL)
        self.progress = ttk.Progressbar(
            self.root, style="minimal.Horizontal.TProgressbar",
            mode="indeterminate")
        self.progress.pack(fill="x")

        # COLUMN HEADER
        table = tk.Frame(self.root, bg=BG_MAIN)
        table.pack(fill="both", expand=True)

        col_hdr = tk.Frame(table, bg=BG_HEADER)
        col_hdr.pack(fill="x")
        for text, w in [("Port", 9), ("State", 11), ("Service", 15), ("Version / Info", 44)]:
            tk.Label(col_hdr, text=text,
                     font=("Segoe UI", 9, "bold"),
                     bg=BG_HEADER, fg=TEXT_SEC,
                     width=w, anchor="w",
                     padx=12, pady=7).pack(side="left")

        # RESULTS TEXT
        rf = tk.Frame(table, bg=BG_MAIN)
        rf.pack(fill="both", expand=True)

        self.result_text = tk.Text(
            rf, bg=BG_RESULT, fg=TEXT_PRI,
            font=("Consolas", 10), relief="flat",
            selectbackground="#d0d0d0",
            insertbackground=ACCENT,
            state="disabled", wrap="none",
            padx=8, pady=6)

        sy = tk.Scrollbar(rf, command=self.result_text.yview,
                          bg=BG_PANEL, troughcolor=BG_RESULT)
        sx = tk.Scrollbar(rf, orient="horizontal",
                          command=self.result_text.xview,
                          bg=BG_PANEL, troughcolor=BG_RESULT)

        self.result_text.configure(yscrollcommand=sy.set,
                                   xscrollcommand=sx.set)
        sy.pack(side="right",  fill="y")
        sx.pack(side="bottom", fill="x")
        self.result_text.pack(side="left", fill="both", expand=True)

        self.result_text.tag_config("open",     foreground=COL_OPEN)
        self.result_text.tag_config("closed",   foreground=COL_CLOSED)
        self.result_text.tag_config("filtered", foreground=COL_FILTERED)
        self.result_text.tag_config("info",     foreground=COL_INFO)
        self.result_text.tag_config("header",   foreground=TEXT_PRI,
                                    font=("Consolas", 10, "bold"))
        self.result_text.tag_config("sep",      foreground=COL_SEP)
        self.result_text.tag_config("os",       foreground=COL_OS)
        self.result_text.tag_config("dim",      foreground=TEXT_DIM)

        # FOOTER
        tk.Frame(self.root, bg=COL_SEP, height=1).pack(fill="x")
        self.summary_var = tk.StringVar(value="")
        tk.Label(self.root, textvariable=self.summary_var,
                 font=("Segoe UI", 10), bg=BG_PANEL,
                 fg=TEXT_SEC, anchor="w").pack(fill="x", padx=28, pady=7)

    # ══════════════════════════════════════════
    #  IDLE ANIMATIONS
    # ══════════════════════════════════════════
    def _start_idle_animations(self):
        self._animate_radar()

    # ── RADAR SPINNER (top-right canvas) ──────
    def _draw_radar(self, angle):
        c = self.radar_canvas
        c.delete("all")
        cx, cy, r = 26, 26, 20

        # outer circle
        c.create_oval(cx-r, cy-r, cx+r, cy+r,
                      outline=COL_SEP, width=1.5)
        # cross hairs
        c.create_line(cx-r, cy, cx+r, cy, fill=COL_SEP, width=1)
        c.create_line(cx, cy-r, cx, cy+r, fill=COL_SEP, width=1)

        # sweep line
        rad = math.radians(angle)
        x2  = cx + r * math.cos(rad)
        y2  = cy - r * math.sin(rad)
        c.create_line(cx, cy, x2, y2,
                      fill=ACCENT if not self.scan_running else "#1a7a3a",
                      width=2)

        # blip dots at random-ish angles (fixed so they dont flicker)
        for blip_angle, blip_r in [(45, 12), (130, 8), (250, 15), (310, 6)]:
            br  = math.radians(blip_angle)
            bx  = cx + blip_r * math.cos(br)
            by  = cy - blip_r * math.sin(br)
            diff = abs((angle - blip_angle) % 360)
            # fade based on how recently the sweep passed
            alpha = max(0, 1 - diff / 180)
            if alpha > 0.1:
                col = "#1a7a3a" if self.scan_running else ACCENT
                c.create_oval(bx-2, by-2, bx+2, by+2,
                              fill=col, outline="")

        # center dot
        c.create_oval(cx-3, cy-3, cx+3, cy+3,
                      fill=ACCENT if not self.scan_running else "#1a7a3a",
                      outline="")

    def _animate_radar(self):
        self._radar_angle = (self._radar_angle + 4) % 360
        self._draw_radar(self._radar_angle)
        speed = 30 if self.scan_running else 60
        self._radar_job = self.root.after(speed, self._animate_radar)

    # ══════════════════════════════════════════
    #  SCAN ANIMATIONS
    # ══════════════════════════════════════════

    # ── ANIMATED DOT STATUS (Scanning . / .. / ...) ─
    def _start_dot_animation(self, base_text):
        self._dot_base = base_text
        self._dot_count = 0
        self._animate_dots()

    def _animate_dots(self):
        if not self.scan_running:
            return
        dots = "." * (self._dot_count % 4)
        self.status_var.set(f"{self._dot_base}{dots}")
        self._dot_count += 1
        self._dot_job = self.root.after(400, self._animate_dots)

    def _stop_dot_animation(self):
        if self._dot_job:
            self.root.after_cancel(self._dot_job)
            self._dot_job = None

    # ── BUTTON PULSE (colour flicker on Start btn) ─
    def _start_pulse(self):
        self._pulse_val = 0
        self._pulse_up  = True
        self._animate_pulse()

    def _animate_pulse(self):
        if not self.scan_running:
            self.scan_btn.configure(bg=ACCENT)
            return
        # oscillate between ACCENT (#222) and a mid-grey
        if self._pulse_up:
            self._pulse_val += 18
            if self._pulse_val >= 90: self._pulse_up = False
        else:
            self._pulse_val -= 18
            if self._pulse_val <= 0:  self._pulse_up = True

        v  = self._pulse_val
        r  = min(0x22 + v, 0x88)
        g  = min(0x22 + v, 0x88)
        b  = min(0x22 + v, 0x88)
        col = f"#{r:02x}{g:02x}{b:02x}"
        self.scan_btn.configure(bg=col)
        self._pulse_job = self.root.after(60, self._animate_pulse)

    def _stop_pulse(self):
        if self._pulse_job:
            self.root.after_cancel(self._pulse_job)
            self._pulse_job = None
        self.scan_btn.configure(bg=ACCENT)

    # ── TYPEWRITER EFFECT for results ────────────
    def _type_write(self, text, tag=""):
        """Queue a line for typewriter insertion."""
        self._type_queue.append((text, tag))
        if self._type_job is None:
            self._flush_type_queue()

    def _flush_type_queue(self):
        if not self._type_queue:
            self._type_job = None
            return
        text, tag = self._type_queue.pop(0)
        self._insert_char_by_char(text, tag, 0)

    def _insert_char_by_char(self, text, tag, idx):
        if idx >= len(text):
            self._type_job = self.root.after(1, self._flush_type_queue)
            return
        # insert one character
        self.result_text.config(state="normal")
        ch = text[idx]
        if tag:
            self.result_text.insert("end", ch, tag)
        else:
            self.result_text.insert("end", ch)
        self.result_text.see("end")
        self.result_text.config(state="disabled")
        # newline chars are instant; visible chars have a tiny delay
        delay = 0 if ch in ("\n", " ") else 6
        self._type_job = self.root.after(
            delay, self._insert_char_by_char, text, tag, idx + 1)

    def _cancel_typewriter(self):
        if self._type_job:
            self.root.after_cancel(self._type_job)
            self._type_job = None
        self._type_queue.clear()

    # ══════════════════════════════════════════
    #  START SCAN
    # ══════════════════════════════════════════
    def start_scan(self):
        ip = self.ip_var.get().strip()
        try:
            ps = int(self.port_start.get())
            pe = int(self.port_end.get())
        except ValueError:
            messagebox.showerror("Error", "Port values must be numbers.")
            return
        if not ip:
            messagebox.showerror("Error", "Please enter a target IP or hostname.")
            return
        if not (1 <= ps <= 65535 and 1 <= pe <= 65535):
            messagebox.showerror("Error", "Ports must be between 1 and 65535.")
            return
        if ps > pe:
            messagebox.showerror("Error", "Start port must be <= end port.")
            return

        self.scan_running = True
        self.scan_results = []
        self.clear_results()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.start(10)
        self.start_time = datetime.datetime.now()
        self._tick_timer()

        # ── start scan animations ──
        self._start_pulse()
        self._start_dot_animation(f"Scanning  {ip}  (ports {ps}-{pe})")

        args = ""
        if self.service_detect.get(): args += "-sV "
        if self.os_detect.get():      args += "-O "
        args = args.strip()

        # typewriter for header lines
        self._type_write(f"  Started   :  {self.start_time.strftime('%Y-%m-%d  %H:%M:%S')}\n", "info")
        self._type_write(f"  Target    :  {ip}\n", "info")
        self._type_write(f"  Ports     :  {ps} - {pe}\n", "info")
        self._type_write(f"  Options   :  {args or 'default'}\n", "info")
        self._type_write("  " + "-" * 72 + "\n", "sep")

        threading.Thread(target=self._run_scan,
                         args=(ip, ps, pe, args), daemon=True).start()

    # ══════════════════════════════════════════
    #  SCAN THREAD
    # ══════════════════════════════════════════
    def _run_scan(self, ip, ps, pe, args):
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, f"{ps}-{pe}", arguments=args)

            if not self.scan_running:
                self.root.after(0, self._on_stopped)
                return

            open_n = closed_n = filtered_n = 0

            for host in nm.all_hosts():
                hn = nm[host].hostname()
                self._later(f"\n  Host   :  {host}{'  (' + hn + ')' if hn else ''}\n", "header")
                self._later(f"  State  :  {nm[host].state()}\n", "info")

                if self.os_detect.get():
                    try:
                        osm = nm[host].get("osmatch", [])
                        if osm:
                            self._later(
                                f"  OS     :  {osm[0].get('name','?')}  "
                                f"(accuracy {osm[0].get('accuracy','?')}%)\n", "os")
                    except Exception:
                        pass

                self._later("  " + "-" * 72 + "\n", "sep")

                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        if not self.scan_running:
                            break
                        d       = nm[host][proto][port]
                        state   = d.get("state", "?")
                        service = d.get("name") or get_service(port)
                        ver     = " ".join(filter(None, [
                            d.get("product",""), d.get("version",""),
                            d.get("extrainfo","")])).strip() or "-"

                        line = f"  {str(port):<9}{state:<13}{service:<17}{ver}\n"
                        tag  = ("open"     if state == "open"     else
                                "filtered" if state == "filtered" else "closed")

                        self.scan_results.append(
                            {"port": port, "state": state,
                             "service": service, "version": ver})

                        self._later(line, tag)

                        if state == "open":     open_n     += 1
                        elif state == "closed": closed_n   += 1
                        else:                   filtered_n += 1

            self.root.after(0, lambda o=open_n, c=closed_n, f=filtered_n:
                            self._on_done(o, c, f))
        except nmap.PortScannerError as e:
            self.root.after(0, lambda: self._on_error(str(e)))
        except Exception as e:
            self.root.after(0, lambda: self._on_error(str(e)))

    # ══════════════════════════════════════════
    #  COMPLETION HANDLERS
    # ══════════════════════════════════════════
    def _on_done(self, o, c, f):
        elapsed = (datetime.datetime.now() - self.start_time).total_seconds()
        self._later("\n  " + "-" * 72 + "\n", "sep")
        self._later(f"  Finished in {elapsed:.1f}s\n", "info")
        self._later(f"  Open: {o}    Closed: {c}    Filtered: {f}\n", "info")
        self.summary_var.set(
            f"  Open: {o}     Closed: {c}     Filtered: {f}     .  {elapsed:.1f}s")
        self._stop_dot_animation()
        self._stop_pulse()
        self.status_var.set("Scan complete.")
        self.timer_var.set("")
        self._reset_ui()

    def _on_stopped(self):
        self._later("\n  [ Scan stopped by user ]\n", "dim")
        self._stop_dot_animation()
        self._stop_pulse()
        self.status_var.set("Stopped.")
        self.timer_var.set("")
        self._reset_ui()

    def _on_error(self, msg):
        self._later(f"\n  [ Error ]  {msg}\n", "closed")
        self._stop_dot_animation()
        self._stop_pulse()
        self.status_var.set("Error during scan.")
        self.timer_var.set("")
        self._reset_ui()
        messagebox.showerror("Scan Error",
                             f"{msg}\n\nMake sure Nmap is installed and "
                             "you have the required permissions.")

    def _reset_ui(self):
        self.scan_running = False
        self.progress.stop()
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    # ──────────────────────────────────────────
    #  HELPERS
    # ──────────────────────────────────────────
    def _later(self, text, tag=""):
        """Thread-safe: queue text via typewriter on main thread."""
        self.root.after(0, lambda t=text, g=tag: self._type_write(t, g))

    def _write(self, text, tag=""):
        self.result_text.config(state="normal")
        self.result_text.insert("end", text, tag if tag else ())
        self.result_text.see("end")
        self.result_text.config(state="disabled")

    def _tick_timer(self):
        if self.scan_running and self.start_time:
            e = (datetime.datetime.now() - self.start_time).total_seconds()
            self.timer_var.set(f"Elapsed:  {int(e)}s")
            self.root.after(1000, self._tick_timer)

    def stop_scan(self):
        self.scan_running = False
        self._stop_dot_animation()
        self._stop_pulse()
        self.status_var.set("Stopping ...")

    # ──────────────────────────────────────────
    #  SAVE
    # ──────────────────────────────────────────
    def save_results(self):
        if not self.scan_results:
            messagebox.showinfo("Nothing to Save", "Run a scan first.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text File","*.txt"),("CSV File","*.csv"),("All","*.*")],
            title="Save Results")
        if not fp: return
        try:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(fp, "w", encoding="utf-8") as f:
                if fp.endswith(".csv"):
                    f.write("Port,State,Service,Version\n")
                    for r in self.scan_results:
                        f.write(f"{r['port']},{r['state']},{r['service']},{r['version']}\n")
                else:
                    f.write("=" * 60 + "\n")
                    f.write("  Network Port Scanner - Scan Report\n")
                    f.write("=" * 60 + "\n")
                    f.write(f"  Saved  : {now}\n")
                    f.write(f"  Target : {self.ip_var.get()}\n")
                    f.write(f"  Ports  : {self.port_start.get()}-{self.port_end.get()}\n")
                    f.write("-" * 60 + "\n")
                    f.write(f"  {'Port':<9}{'State':<13}{'Service':<17}Version\n")
                    f.write("-" * 60 + "\n")
                    for r in self.scan_results:
                        f.write(f"  {str(r['port']):<9}{r['state']:<13}"
                                f"{r['service']:<17}{r['version']}\n")
                    f.write("=" * 60 + "\n")
            messagebox.showinfo("Saved", f"Results saved to:\n{fp}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    # ──────────────────────────────────────────
    #  CLEAR
    # ──────────────────────────────────────────
    def clear_results(self):
        self._cancel_typewriter()
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.config(state="disabled")
        self.summary_var.set("")
        self.status_var.set("Ready  -  enter a target and press Start Scan.")
        self.scan_results = []


if __name__ == "__main__":
    root = tk.Tk()
    app  = PortScannerApp(root)
    root.mainloop()
