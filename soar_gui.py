import customtkinter as ctk
import tkinter as tk
import os
import subprocess
import sys
import threading
from pathlib import Path

from soar_service import SOARService
from enrichment_worker import EnrichmentWorker
from tkinter import ttk, messagebox

# ==========================================
# MODULE 1: SYSTEM SETUP & CONFIG
# ==========================================
try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg_main": "#1a1c1e",
    "bg_card": "#212325",
    "bg_panel": "#2a2d2e",
    "critical": "#FF4B4B",
    "high": "#FCA311",
    "medium": "#E0A96D",
    "low": "#00D26A",
    "text_light": "#e2e8f0",
    "text_muted": "#8c92ac",
    "accent": "#1f538d",
    "state_new": "#3498db",
    "state_assigned": "#9b59b6",
    "state_investigating": "#e67e22",
    "state_closed": "#95a5a6",
    "state_escalated": "#e74c3c"
}

# Queue performance settings.
QUEUE_COLUMNS = 2
QUEUE_ROWS = 4
QUEUE_PAGE_SIZE = QUEUE_COLUMNS * QUEUE_ROWS  # 8 cards per page
NEW_ALERT_ANIMATION_MS = 180

# ==========================================
# MODULE 2: WAZUH READER LIFECYCLE
# ==========================================
class WazuhReaderManager:
    """Manage the lifecycle of the external Wazuh reader process.

    The reader remains a separate process so the GUI stays responsive and
    the existing reconnect/deduplication behavior in wazuh_reader.py is
    preserved. The GUI owns the process lifecycle: start, monitor, restart
    after an unexpected exit, and stop during application shutdown.
    """

    RESTART_DELAY_SECONDS = 5

    def __init__(self, on_status_change=None, on_alert_created=None):
        self.on_status_change = on_status_change
        self.on_alert_created = on_alert_created
        self.process = None
        self.monitor_thread = None
        self.stop_requested = False
        self._lock = threading.Lock()

        self.reader_path = Path(__file__).resolve().with_name(
            "wazuh_reader.py"
        )

    def _notify_status(self, status):
        if self.on_status_change is not None:
            try:
                self.on_status_change(status)
            except Exception:
                pass

    def start(self):
        """Start the Wazuh reader if it is configured and not already running."""

        if not os.environ.get("WAZUH_HOST", "").strip():
            self._notify_status("Not configured (set WAZUH_HOST)")
            return False

        with self._lock:
            if self.stop_requested:
                return False

            if not self.reader_path.exists():
                self._notify_status("Missing reader")
                return False

            if self.process is not None and self.process.poll() is None:
                self._notify_status("Running")
                return True

            command = [
                sys.executable,
                str(self.reader_path),
                "--mode",
                "follow"
            ]

            try:
                startupinfo = None
                creationflags = 0

                if os.name == "nt":
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    creationflags = getattr(
                        subprocess,
                        "CREATE_NO_WINDOW",
                        0
                    )

                self.process = subprocess.Popen(
                    command,
                    cwd=str(self.reader_path.parent),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    startupinfo=startupinfo,
                    creationflags=creationflags
                )

                self._notify_status("Starting")

                self.monitor_thread = threading.Thread(
                    target=self._monitor_process,
                    daemon=True,
                    name="WazuhReaderMonitor"
                )
                self.monitor_thread.start()

                return True

            except Exception as exc:
                self.process = None
                self._notify_status(f"Error: {exc}")
                return False

    def _monitor_process(self):
        """Consume reader output and restart after unexpected termination."""

        process = self.process

        if process is None:
            return

        try:
            if process.stdout is not None:
                for raw_line in process.stdout:
                    line = raw_line.strip()

                    if not line:
                        continue

                    if line.startswith("[CREATED]"):
                        if self.on_alert_created is not None:
                            try:
                                self.on_alert_created()
                            except Exception:
                                pass
                    elif line.startswith("[ERROR]") or line.startswith("[SSH STDERR]"):
                        self._notify_status("Error")
                    elif line.startswith("[CONNECT]"):
                        self._notify_status("Running")

        except Exception:
            pass

        try:
            return_code = process.wait()
        except Exception:
            return_code = None

        with self._lock:
            if self.process is process:
                self.process = None

            stopping = self.stop_requested

        if stopping:
            self._notify_status("Stopped")
            return

        if return_code == 0:
            self._notify_status("Stopped")
        else:
            self._notify_status("Disconnected")

        # Let the Tk event loop schedule the restart. This avoids trying to
        # manipulate GUI state directly from the monitor thread.
        callback = getattr(self, "restart_callback", None)
        if callback is not None:
            try:
                callback(self.RESTART_DELAY_SECONDS)
            except Exception:
                pass

    def set_restart_callback(self, callback):
        """Set a callback used to schedule an automatic restart."""
        self.restart_callback = callback

    def stop(self):
        """Stop the reader process and its child SSH process tree."""

        with self._lock:
            self.stop_requested = True
            process = self.process

        if process is None:
            self._notify_status("Stopped")
            return

        try:
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(
                        [
                            "taskkill",
                            "/PID",
                            str(process.pid),
                            "/T",
                            "/F"
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False
                    )
                else:
                    process.terminate()

                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()

        except Exception:
            try:
                process.kill()
            except Exception:
                pass

        with self._lock:
            if self.process is process:
                self.process = None

        self._notify_status("Stopped")


# ==========================================
# MODULE 3: REUSABLE UI COMPONENTS
# ==========================================
class MetricCard(ctk.CTkFrame):
    def __init__(self, parent, title, initial_value, color):
        super().__init__(parent, corner_radius=8, fg_color=COLORS["bg_card"])
        lbl_title = ctk.CTkLabel(self, text=title, font=("Segoe UI", 12, "bold"), text_color=COLORS["text_muted"])
        lbl_title.pack(pady=(10, 0))
        self.lbl_val = ctk.CTkLabel(self, text=str(initial_value), font=("Segoe UI", 28, "bold"), text_color=color)
        self.lbl_val.pack(pady=(0, 10))

    def set_value(self, val):
        self.lbl_val.configure(text=str(val))

class Badge(ctk.CTkFrame):
    def __init__(self, parent, text, color):
        super().__init__(parent, corner_radius=4, fg_color=color)
        self.label = ctk.CTkLabel(
            self,
            text=text.upper(),
            font=("Segoe UI", 10, "bold"),
            text_color="#ffffff"
        )
        self.label.pack(padx=6, pady=2)

    def set_data(self, text, color):
        self.configure(fg_color=color)
        self.label.configure(text=text.upper())

class SmoothScrollFrame(ctk.CTkScrollableFrame):
    """
    CTkScrollableFrame with one consistent mouse-wheel step.

    The stock widget scrolls by a fraction of the visible height per wheel
    notch, which feels very different depending on window size. This version
    scrolls a fixed number of pixels per notch and only reacts to wheel events
    that happen over its own content (not over dialogs or other pages).
    """

    SCROLL_UNIT_PX = 24
    UNITS_PER_NOTCH = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            self._parent_canvas.configure(
                yscrollincrement=self.SCROLL_UNIT_PX
            )
        except tk.TclError:
            pass

    def _owns_widget(self, widget):
        node = widget

        while node is not None:
            if node is self:
                return True

            node = getattr(node, "master", None)

        return False

    def _mouse_wheel_all(self, event):
        if not self._owns_widget(event.widget):
            return

        try:
            if self._parent_canvas.yview() == (0.0, 1.0):
                return  # Everything already fits; nothing to scroll.

            delta = getattr(event, "delta", 0)

            if delta:
                steps = int(-delta / 120 * self.UNITS_PER_NOTCH)

                if steps == 0:
                    steps = -1 if delta > 0 else 1

            else:
                steps = (
                    -self.UNITS_PER_NOTCH
                    if getattr(event, "num", 0) == 4
                    else self.UNITS_PER_NOTCH
                )

            self._parent_canvas.yview_scroll(steps, "units")

        except tk.TclError:
            pass


def _clip(text, limit):
    text = str(text)

    if len(text) <= limit:
        return text

    return text[: limit - 1].rstrip() + "…"


class AlertCard(ctk.CTkFrame):
    """Compact rectangular alert card (designed for a 2-column grid)."""

    DESC_LIMIT = 58
    DETAILS_LIMIT = 62

    def __init__(self, parent, alert_data, click_callback, current_user):
        super().__init__(
            parent,
            corner_radius=8,
            fg_color=COLORS["bg_card"],
            border_width=0,
            cursor="hand2"
        )

        self.alert_data = dict(alert_data)
        self.click_callback = click_callback
        self.current_user = current_user
        self._rendered_key = None

        self.grid_columnconfigure(1, weight=1)

        for row in range(4):
            self.grid_rowconfigure(row, weight=1)

        # height=1: a childless CTkFrame otherwise requests its 200px
        # default height, which would make every card 200px tall.
        self.strip = ctk.CTkFrame(
            self,
            width=6,
            height=1,
            fg_color=COLORS["low"],
            corner_radius=0
        )
        self.strip.grid(row=0, column=0, rowspan=4, sticky="ns")

        # Row 0: ID + severity + state
        self.header_frm = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frm.grid(
            row=0, column=1, sticky="ew", padx=10, pady=(6, 0)
        )

        self.id_label = ctk.CTkLabel(
            self.header_frm,
            text="",
            height=20,
            font=("Segoe UI", 11, "bold"),
            text_color=COLORS["text_muted"]
        )
        self.id_label.pack(side="left", padx=(0, 8))

        self.severity_badge = Badge(
            self.header_frm, "LOW", COLORS["low"]
        )
        self.severity_badge.pack(side="left", padx=(0, 5))

        self.state_badge = Badge(
            self.header_frm, "NEW", COLORS["state_new"]
        )
        self.state_badge.pack(side="left")

        # Row 1: rule description
        self.desc_label = ctk.CTkLabel(
            self,
            text="",
            anchor="w",
            height=22,
            font=("Segoe UI", 14, "bold")
        )
        self.desc_label.grid(row=1, column=1, sticky="ew", padx=10)

        # Row 2: source -> destination • service
        self.details_label = ctk.CTkLabel(
            self,
            text="",
            anchor="w",
            height=20,
            font=("Segoe UI", 12),
            text_color=COLORS["text_light"]
        )
        self.details_label.grid(
            row=2, column=1, sticky="ew", padx=10
        )

        # Row 3: assignee (left) + timestamp (right)
        self.footer_frm = ctk.CTkFrame(self, fg_color="transparent")
        self.footer_frm.grid(
            row=3, column=1, sticky="ew", padx=10, pady=(0, 6)
        )

        self.assignee_label = ctk.CTkLabel(
            self.footer_frm,
            text="",
            height=18,
            font=("Segoe UI", 11, "italic"),
            text_color=COLORS["text_muted"]
        )
        self.assignee_label.pack(side="left")

        self.time_label = ctk.CTkLabel(
            self.footer_frm,
            text="",
            height=18,
            font=("Segoe UI", 10),
            text_color=COLORS["text_muted"]
        )
        self.time_label.pack(side="right")

        # Bind each CTk widget exactly once (CTk's bind already reaches its
        # inner canvas/label, so recursing into children would double-fire).
        for widget in (
            self,
            self.strip,
            self.header_frm,
            self.id_label,
            self.severity_badge,
            self.severity_badge.label,
            self.state_badge,
            self.state_badge.label,
            self.desc_label,
            self.details_label,
            self.footer_frm,
            self.assignee_label,
            self.time_label
        ):
            widget.bind("<Button-1>", self._on_click)

        self.update_data(alert_data, current_user)

    def _on_click(self, event=None):
        self.click_callback(self.alert_data["id"])

    def update_data(self, alert_data, current_user=None):
        """Update displayed values without destroying the card widget."""

        if current_user is not None:
            self.current_user = current_user

        new_data = dict(alert_data)

        key = (
            new_data.get("id"),
            new_data.get("severity"),
            new_data.get("state"),
            new_data.get("rule_desc"),
            new_data.get("timestamp"),
            new_data.get("src_ip"),
            new_data.get("dst_ip"),
            new_data.get("service"),
            new_data.get("assignee"),
            self.current_user
        )

        self.alert_data = new_data

        if key == self._rendered_key:
            return  # Nothing visible changed; skip the widget updates.

        self._rendered_key = key

        severity = new_data.get("severity") or "UNKNOWN"
        state = new_data.get("state") or "UNKNOWN"

        sev_color = COLORS.get(severity.lower(), COLORS["text_light"])
        state_color = COLORS.get(
            f"state_{state.lower()}", COLORS["text_muted"]
        )

        self.strip.configure(fg_color=sev_color)
        self.id_label.configure(text=str(new_data.get("id", "-")))
        self.severity_badge.set_data(severity, sev_color)
        self.state_badge.set_data(state, state_color)

        self.desc_label.configure(
            text=_clip(new_data.get("rule_desc") or "-", self.DESC_LIMIT)
        )

        src_ip = new_data.get("src_ip") or "-"
        dst_ip = new_data.get("dst_ip") or "-"
        service = new_data.get("service") or "-"

        self.details_label.configure(
            text=_clip(
                f"{src_ip} → {dst_ip}  •  {service}",
                self.DETAILS_LIMIT
            )
        )

        assignee = new_data.get("assignee") or "Unassigned"

        self.assignee_label.configure(
            text=(
                "Assigned to: You"
                if assignee == self.current_user
                else f"Assigned to: {assignee}"
            )
        )

        self.time_label.configure(text=str(new_data.get("timestamp") or "-"))

    def flash(self, duration_ms=NEW_ALERT_ANIMATION_MS * 5):
        """Briefly outline a newly arrived card."""

        try:
            self.configure(
                border_width=2,
                border_color=COLORS["state_new"]
            )
        except tk.TclError:
            return

        self.after(duration_ms, self._clear_flash)

    def _clear_flash(self):
        try:
            if self.winfo_exists():
                self.configure(border_width=0)
        except tk.TclError:
            pass


# ==========================================
# MODULE 4: DIALOGS (MODALS)
# ==========================================
class CloseAlertDialog(ctk.CTkToplevel):
    def __init__(self, parent, alert_id, submit_callback, success_callback):
        super().__init__(parent)
        self.title(f"Close Alert - {alert_id}")
        self.geometry("450x400")
        self.grab_set()
        self.success_callback = success_callback
        self.submit_callback = submit_callback
        self.alert_id = alert_id

        ctk.CTkLabel(
            self,
            text="Disposition (Required):",
            font=("Segoe UI", 12, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )

        self.disp_var = ctk.StringVar(value="True Positive")

        opts = [
            "True Positive",
            "False Positive",
            "Benign",
            "Duplicate",
            "Other"
        ]

        ctk.CTkOptionMenu(
            self,
            variable=self.disp_var,
            values=opts
        ).pack(
            fill="x",
            padx=20
        )

        ctk.CTkLabel(
            self,
            text="Closing Notes (Optional):",
            font=("Segoe UI", 12, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(15, 5)
        )

        self.txt_notes = ctk.CTkTextbox(
            self,
            height=120
        )
        self.txt_notes.pack(
            fill="x",
            padx=20
        )

        btn_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        btn_frame.pack(
            fill="x",
            padx=20,
            pady=20
        )

        ctk.CTkButton(
            btn_frame,
            text="Cancel",
            fg_color="transparent",
            border_width=1,
            command=self.destroy
        ).pack(
            side="left",
            expand=True,
            padx=5
        )

        ctk.CTkButton(
            btn_frame,
            text="Confirm Close",
            fg_color=COLORS["state_closed"],
            command=self.submit
        ).pack(
            side="right",
            expand=True,
            padx=5
        )

    def submit(self):
        disposition = self.disp_var.get()
        notes = self.txt_notes.get(
            "1.0",
            tk.END
        ).strip()

        try:
            self.submit_callback(
                disposition,
                notes
            )

        except (
            ValueError,
            PermissionError,
            RuntimeError
        ) as exc:
            messagebox.showerror(
                "Unable to Close Alert",
                str(exc),
                parent=self
            )
            return

        self.success_callback()
        self.destroy()


class EscalateAlertDialog(ctk.CTkToplevel):
    def __init__(self, parent, alert_id, submit_callback, success_callback):
        super().__init__(parent)
        self.title(f"Escalate to Manager - {alert_id}")
        self.geometry("600x650")
        self.grab_set()
        self.success_callback = success_callback
        self.alert_id = alert_id
        self.submit_callback = submit_callback
        
        ctk.CTkLabel(self, text="MANDATORY INVESTIGATION REPORT", font=("Segoe UI", 14, "bold"), text_color=COLORS["critical"]).pack(pady=10)
        
        self.fields = {}
        def add_field(label, height=80):
            ctk.CTkLabel(self, text=label, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=20, pady=(5,0))
            txt = ctk.CTkTextbox(self, height=height)
            txt.pack(fill="x", padx=20)
            txt.bind("<KeyRelease>", self.validate)
            return txt
            
        self.fields['summary'] = add_field("Executive Summary *")
        self.fields['evidence'] = add_field("Evidence Collected *")
        self.fields['findings'] = add_field("Investigation Findings *")
        self.fields['recommendation'] = add_field("Recommended Action *")
        
        self.btn_submit = ctk.CTkButton(self, text="Submit Escalation", fg_color=COLORS["critical"], state="disabled", command=self.submit)
        self.btn_submit.pack(pady=20)
        
    def validate(self, event=None):
        if all(len(f.get("1.0", tk.END).strip()) > 5 for f in self.fields.values()):
            self.btn_submit.configure(state="normal")
        else:
            self.btn_submit.configure(state="disabled")

    def submit(self):
        data = {
            k: v.get("1.0", tk.END).strip()
            for k, v in self.fields.items()
        }

        try:
            self.submit_callback(data)

        except (ValueError, PermissionError, RuntimeError) as exc:
            messagebox.showerror(
                "Unable to Escalate Alert",
                str(exc),
                parent=self
            )
            return

        self.success_callback()
        self.destroy()

class IOCDetailDialog(ctk.CTkToplevel):
    def __init__(self, parent, ioc_val, intel_data):
        super().__init__(parent)
        self.title(f"Cached Intelligence - {ioc_val}")
        self.geometry("400x350")
        self.grab_set()
        
        ctk.CTkLabel(self, text=f"IOC: {ioc_val}", font=("Segoe UI", 16, "bold")).pack(pady=(20, 10))
        
        f = ctk.CTkFrame(self, fg_color=COLORS["bg_card"])
        f.pack(fill="both", expand=True, padx=20, pady=10)
        
        for k, v in intel_data.items():
            row = ctk.CTkFrame(f, fg_color="transparent")
            row.pack(fill="x", pady=4, padx=10)
            ctk.CTkLabel(row, text=k.title().replace("_", " ")+":", width=120, anchor="w", text_color=COLORS["text_muted"], font=("Segoe UI", 12, "bold")).pack(side="left")
            ctk.CTkLabel(row, text=v, anchor="w").pack(side="left")
            
        ctk.CTkButton(self, text="Close", command=self.destroy).pack(pady=20)

# ==========================================
# MODULE 5: PAGES
# ==========================================
class BaseQueuePage(ctk.CTkFrame):
    PAGE_SIZE = QUEUE_PAGE_SIZE

    def __init__(
        self,
        parent,
        nav_callback,
        service,
        title,
        default_filter,
        tabs
    ):
        super().__init__(
            parent,
            fg_color="transparent"
        )

        self.nav_callback = nav_callback
        self.service = service
        self.current_filter = default_filter

        self.page_index = 0
        self._source_alerts = []
        self._filtered_alerts = []
        self._displayed_ids = set()
        self._known_alert_ids = set()
        self._pending_new_data = False
        self._card_pool = []

        ctk.CTkLabel(
            self,
            text=title,
            font=("Segoe UI", 24, "bold")
        ).pack(
            anchor="w",
            pady=(0, 10)
        )

        self.stats_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.stats_frame.pack(
            fill="x",
            pady=(0, 15)
        )
        self.cards = {}

        filter_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        filter_frame.pack(
            fill="x",
            pady=10
        )

        self.seg_button = ctk.CTkSegmentedButton(
            filter_frame,
            values=tabs,
            command=self.set_filter
        )
        self.seg_button.pack(
            side="left"
        )
        self.seg_button.set(default_filter)

        self.search_var = ctk.StringVar()

        self.search_var.trace_add(
            "write",
            lambda *args: self._on_search_changed()
        )

        ctk.CTkEntry(
            filter_frame,
            textvariable=self.search_var,
            placeholder_text="Search alerts...",
            width=250
        ).pack(
            side="right",
            padx=5
        )

        self.refresh_button = ctk.CTkButton(
            filter_frame,
            text="Refresh Queue",
            width=135,
            command=self.refresh_data
        )
        self.refresh_button.pack(
            side="right",
            padx=5
        )

        self.refresh_status = ctk.CTkLabel(
            filter_frame,
            text="Not refreshed",
            font=("Segoe UI", 10),
            text_color=COLORS["text_muted"]
        )
        self.refresh_status.pack(
            side="right",
            padx=5
        )

        # Each page holds QUEUE_PAGE_SIZE cards in a fixed grid, so the queue
        # never needs to scroll. Paging replaces scrolling.
        self.queue_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.queue_frame.pack(
            fill="both",
            expand=True
        )

        for column in range(QUEUE_COLUMNS):
            self.queue_frame.grid_columnconfigure(
                column,
                weight=1,
                uniform="queue_column"
            )

        # Equal-height rows that share all available height, so the cards
        # fill the page whatever the window size.
        for row in range(QUEUE_ROWS):
            self.queue_frame.grid_rowconfigure(
                row,
                weight=1,
                uniform="queue_row"
            )

        self.lbl_empty = ctk.CTkLabel(
            self.queue_frame,
            text="",
            text_color=COLORS["text_muted"]
        )

        self.pagination_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.pagination_frame.pack(
            fill="x",
            pady=(8, 0)
        )

        self.prev_button = ctk.CTkButton(
            self.pagination_frame,
            text="← Previous",
            width=110,
            command=self.previous_page,
            state="disabled"
        )
        self.prev_button.pack(side="left")

        self.page_label = ctk.CTkLabel(
            self.pagination_frame,
            text="Page 1 of 1 • 0 alerts",
            font=("Segoe UI", 11, "bold"),
            text_color=COLORS["text_muted"]
        )
        self.page_label.pack(
            side="left",
            expand=True
        )

        self.next_button = ctk.CTkButton(
            self.pagination_frame,
            text="Next →",
            width=110,
            command=self.next_page,
            state="disabled"
        )
        self.next_button.pack(side="right")

    def _on_search_changed(self):
        self.page_index = 0
        self._render_filtered_page()

    def set_filter(self, value):
        self.current_filter = value
        self.page_index = 0
        self._render_filtered_page()

    def get_source_data(self):
        return self.service.get_alert_queue()

    def load_data(self, alerts=None):
        """
        Load a fresh queue snapshot and render only the visible page.
        """
        if alerts is None:
            alerts = self.get_source_data()

        self._source_alerts = list(alerts)

        self._known_alert_ids = {
            alert["id"]
            for alert in self._source_alerts
        }

        self._pending_new_data = False

        self.page_index = min(
            self.page_index,
            max(
                0,
                self._total_pages() - 1
            )
        )

        self._render_filtered_page()

        self.refresh_button.configure(
            text="Refresh Queue"
        )

        self.refresh_status.configure(
            text=(
                f"{self._refresh_timestamp_text()} "
                f"• {len(self._source_alerts)} stored"
            )
        )

    def refresh_data(self):
        """
        Manually refresh the logical queue.

        New alerts are detected against the last GUI snapshot. If new
        alerts exist, the UI moves to page 1 so those alerts are immediately
        visible and only the new cards are animated.
        """
        try:
            alerts = list(
                self.get_source_data()
            )

        except Exception as exc:
            messagebox.showerror(
                "Unable to Refresh Queue",
                str(exc),
                parent=self
            )
            return

        previous_ids = set(
            self._known_alert_ids
        )

        new_ids = {
            alert["id"]
            for alert in alerts
            if alert["id"] not in previous_ids
        }

        self._source_alerts = alerts

        self._known_alert_ids = {
            alert["id"]
            for alert in alerts
        }

        self._pending_new_data = False

        if new_ids:
            self.page_index = 0

        self._render_filtered_page(
            animate_new_ids=new_ids
        )

        self.refresh_button.configure(
            text="Refresh Queue"
        )

        self.refresh_status.configure(
            text=(
                f"{self._refresh_timestamp_text(len(new_ids))} "
                f"• {len(self._source_alerts)} stored"
            )
        )

    def mark_new_data_available(self):
        """
        Indicate that the background reader has added data without
        rebuilding any widgets.
        """
        self._pending_new_data = True

        self.refresh_button.configure(
            text="Refresh Queue • New"
        )

        self.refresh_status.configure(
            text="New data available"
        )

    def _refresh_timestamp_text(self, new_count=0):
        timestamp = __import__(
            "datetime"
        ).datetime.now().strftime(
            "%H:%M:%S"
        )

        suffix = (
            f" • {new_count} new"
            if new_count
            else ""
        )

        return f"Updated {timestamp}{suffix}"

    def _apply_filters(self):
        query = (
            self.search_var.get()
            .strip()
            .lower()
        )

        filtered = []

        for alert in self._source_alerts:
            state = alert.get("state")
            severity = alert.get("severity")
            assignee = (
                alert.get("assignee")
                or "Unassigned"
            )

            is_active = state not in [
                "CLOSED",
                "ESCALATED"
            ]

            cf = self.current_filter

            if cf == "All Active" and not is_active:
                continue

            elif cf == "Critical" and (
                severity != "CRITICAL"
                or not is_active
            ):
                continue

            elif cf == "High" and (
                severity != "HIGH"
                or not is_active
            ):
                continue

            elif cf == "Medium" and (
                severity != "MEDIUM"
                or not is_active
            ):
                continue

            elif cf == "Low" and (
                severity != "LOW"
                or not is_active
            ):
                continue

            elif cf == "Unassigned" and (
                assignee != "Unassigned"
                or not is_active
            ):
                continue

            elif cf == "Assigned to Me" and (
                assignee != self.service.current_user
                or not is_active
            ):
                continue

            elif cf == "Investigating" and (
                state != "INVESTIGATING"
            ):
                continue

            elif cf == "Escalated" and (
                state != "ESCALATED"
            ):
                continue

            elif cf == "Closed" and (
                state != "CLOSED"
            ):
                continue

            if query:
                search_str = (
                    f"{alert.get('id', '')} "
                    f"{alert.get('rule_desc', '')} "
                    f"{alert.get('src_ip', '')} "
                    f"{alert.get('dst_ip', '')} "
                    f"{assignee} "
                    f"{severity} "
                    f"{alert.get('rule_id', '')} "
                    f"{alert.get('service', '')} "
                    f"{alert.get('agent', '')}"
                ).lower()

                if query not in search_str:
                    continue

            filtered.append(alert)

        self._filtered_alerts = filtered

    def _render_filtered_page(self, animate_new_ids=None):
        self._apply_filters()

        total_pages = self._total_pages()

        if total_pages == 0:
            self.page_index = 0
        else:
            self.page_index = min(
                self.page_index,
                total_pages - 1
            )

        start_index = self.page_index * self.PAGE_SIZE

        page_alerts = self._filtered_alerts[
            start_index:
            start_index + self.PAGE_SIZE
        ]

        # A fixed pool of cards is reused for every page. Flipping pages
        # only updates labels; no widgets are created or destroyed.
        while len(self._card_pool) < len(page_alerts):
            self._card_pool.append(
                AlertCard(
                    self.queue_frame,
                    page_alerts[len(self._card_pool)],
                    lambda a_id: self.nav_callback(
                        "investigation",
                        alert_id=a_id
                    ),
                    self.service.current_user
                )
            )

        for index, card in enumerate(self._card_pool):
            if index < len(page_alerts):
                card.update_data(
                    page_alerts[index],
                    self.service.current_user
                )
                card.grid(
                    row=index // QUEUE_COLUMNS,
                    column=index % QUEUE_COLUMNS,
                    sticky="nsew",
                    padx=5,
                    pady=4
                )
            else:
                card.grid_remove()

        if not page_alerts:
            self.lbl_empty.grid(
                row=0,
                column=0,
                columnspan=QUEUE_COLUMNS,
                pady=40
            )
            self.lbl_empty.configure(
                text="No alerts match your filter/search."
            )

        else:
            self.lbl_empty.grid_remove()

        self._update_pagination(total_pages)

        self._displayed_ids = {
            alert["id"]
            for alert in page_alerts
        }

        # Outline only the first few new cards so a large ingestion burst
        # never schedules dozens of simultaneous effects.
        if animate_new_ids:
            flashed = 0

            for index, alert in enumerate(page_alerts):
                if alert["id"] in animate_new_ids and flashed < 4:
                    self._card_pool[index].flash()
                    flashed += 1

    def _total_pages(self):
        if not self._filtered_alerts:
            return 0

        return (
            len(self._filtered_alerts)
            + self.PAGE_SIZE
            - 1
        ) // self.PAGE_SIZE

    def _update_pagination(self, total_pages):
        display_pages = max(
            1,
            total_pages
        )

        display_page = (
            self.page_index + 1
            if total_pages
            else 1
        )

        total_count = len(
            self._filtered_alerts
        )

        start_number = (
            self.page_index
            * self.PAGE_SIZE
            + 1
            if total_count
            else 0
        )

        end_number = (
            min(
                start_number
                + self.PAGE_SIZE
                - 1,
                total_count
            )
            if total_count
            else 0
        )

        self.page_label.configure(
            text=(
                f"Page {display_page} of {display_pages}"
                f" • Showing {start_number}-{end_number}"
                f" of {total_count}"
            )
        )

        self.prev_button.configure(
            state=(
                "normal"
                if self.page_index > 0
                else "disabled"
            )
        )

        self.next_button.configure(
            state=(
                "normal"
                if (
                    total_pages
                    and self.page_index
                    < total_pages - 1
                )
                else "disabled"
            )
        )

    def previous_page(self):
        if self.page_index <= 0:
            return

        self.page_index -= 1
        self._render_filtered_page()


    def next_page(self):
        total_pages = self._total_pages()

        if (
            not total_pages
            or self.page_index
            >= total_pages - 1
        ):
            return

        self.page_index += 1
        self._render_filtered_page()



class DashboardPage(BaseQueuePage):
    def __init__(self, parent, nav_callback, service):
        tabs = [
            "All Active",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Unassigned",
            "Assigned to Me",
            "Investigating",
            "Escalated",
            "Closed"
        ]
        super().__init__(
            parent,
            nav_callback,
            service,
            "Alert Queue Dashboard",
            "All Active",
            tabs
        )

        self.cards = {
            "critical": MetricCard(
                self.stats_frame,
                "Critical",
                "0",
                COLORS["critical"]
            ),
            "unassigned": MetricCard(
                self.stats_frame,
                "Unassigned",
                "0",
                COLORS["high"]
            ),
            "my_alerts": MetricCard(
                self.stats_frame,
                "My Active Alerts",
                "0",
                COLORS["accent"]
            )
        }
        for i, card in enumerate(self.cards.values()):
            card.grid(
                row=0,
                column=i,
                padx=5,
                sticky="ew"
            )
            self.stats_frame.grid_columnconfigure(
                i,
                weight=1
            )

    def load_data(self, alerts=None):
        if alerts is None:
            alerts = self.service.get_alert_queue()
        else:
            alerts = list(alerts)

        self.cards["critical"].set_value(
            sum(
                1
                for alert in alerts
                if alert["severity"] == "CRITICAL"
                and alert["state"] not in [
                    "CLOSED",
                    "ESCALATED"
                ]
            )
        )
        self.cards["unassigned"].set_value(
            sum(
                1
                for alert in alerts
                if alert["assignee"] == "Unassigned"
                and alert["state"] not in [
                    "CLOSED",
                    "ESCALATED"
                ]
            )
        )
        self.cards["my_alerts"].set_value(
            sum(
                1
                for alert in alerts
                if alert["assignee"] == self.service.current_user
                and alert["state"] not in [
                    "CLOSED",
                    "ESCALATED"
                ]
            )
        )

        super().load_data(alerts=alerts)


class MyAlertsPage(BaseQueuePage):
    def __init__(self, parent, nav_callback, service):
        tabs = [
            "All Mine",
            "Assigned to Me",
            "Investigating",
            "Escalated",
            "Closed"
        ]
        super().__init__(
            parent,
            nav_callback,
            service,
            "My Alerts",
            "All Mine",
            tabs
        )
        self.stats_frame.pack_forget()

    def get_source_data(self):
        return self.service.get_my_alerts()

class InvestigationPage(ctk.CTkFrame):
    def __init__(self, parent, nav_callback, root_app, service):
        super().__init__(parent, fg_color="transparent")
        self.nav_callback = nav_callback
        self.root_app = root_app 
        self.service = service
        self.alert_id = None
        self._ioc_poll_job = None
        
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.pack(fill="x", pady=(0, 15))
        
        self.lbl_title = ctk.CTkLabel(self.header, text="Investigation Workspace", font=("Segoe UI", 24, "bold"))
        self.lbl_title.pack(side="left")
        
        self.btn_back = ctk.CTkButton(self.header, text="← Back to Queue", fg_color="transparent", border_width=1, width=120, command=lambda: self.nav_callback("dashboard"))
        self.btn_back.pack(side="right")
        
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure(0, weight=4)  
        self.content_frame.grid_columnconfigure(1, weight=5)  
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        self.left_scroll = SmoothScrollFrame(self.content_frame, fg_color="transparent")
        self.left_scroll.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        self.right_scroll = SmoothScrollFrame(self.content_frame, fg_color="transparent")
        self.right_scroll.grid(row=0, column=1, sticky="nsew")
        
        self.frm_overview = self._create_section(self.left_scroll, "Alert Overview")
        self.frm_network = self._create_section(self.left_scroll, "Network & Agent")
        self.frm_raw = self._create_section(self.left_scroll, "Raw Event")
        self.frm_iocs = self._create_section(self.left_scroll, "Extracted IOCs")
        self.frm_timeline = self._create_section(self.left_scroll, "Investigation Timeline")
        
        self.frm_workspace = ctk.CTkFrame(self.right_scroll, fg_color=COLORS["bg_card"])
        self.frm_workspace.pack(fill="both", expand=True, pady=5)
        ctk.CTkLabel(self.frm_workspace, text="Analyst Workspace", font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=10, pady=10)
        
        self.txt_notes = self._add_text_area(self.frm_workspace, "Investigation Notes")
        self.txt_findings = self._add_text_area(self.frm_workspace, "Findings")
        self.txt_evidence = self._add_text_area(self.frm_workspace, "Evidence")
        
        self.frm_actions = ctk.CTkFrame(self.right_scroll, fg_color="transparent", height=60)
        self.frm_actions.pack(fill="x", pady=20)
        
        self.btn_primary = ctk.CTkButton(self.frm_actions, text="Assign to Me")
        self.btn_save = ctk.CTkButton(self.frm_actions, text="Save Workspace", fg_color=COLORS["accent"], command=self.save_workspace)
        self.btn_close = ctk.CTkButton(self.frm_actions, text="Close Alert", fg_color="transparent", border_width=1, command=self.close_alert)
        self.btn_escalate = ctk.CTkButton(self.frm_actions, text="Escalate", fg_color=COLORS["critical"], command=self.escalate_alert)

    def _create_section(self, parent, title):
        frm = ctk.CTkFrame(parent, fg_color=COLORS["bg_panel"])
        frm.pack(fill="x", pady=5)
        ctk.CTkLabel(frm, text=title, font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=10, pady=5)
        content = ctk.CTkFrame(frm, fg_color="transparent")
        content.pack(fill="x", padx=10, pady=(0,10))
        return content
        
    def _add_text_area(self, parent, label):
        ctk.CTkLabel(parent, text=label, font=("Segoe UI", 12, "bold"), text_color=COLORS["text_muted"]).pack(anchor="w", padx=10, pady=(10,2))
        txt = ctk.CTkTextbox(parent, height=80)
        txt.pack(fill="x", padx=10)
        return txt

    def load_alert(self, alert_id):
        self.alert_id = alert_id
        data = self.service.get_alert(alert_id)
        
        self.lbl_title.configure(text=f"Investigation: {alert_id}")
        
        for frm in [self.frm_overview, self.frm_network, self.frm_raw, self.frm_iocs, self.frm_timeline]:
            for w in frm.winfo_children(): w.destroy()

        sev_color = COLORS.get(data["severity"].lower(), COLORS["text_light"])
        self._add_kv(self.frm_overview, "Severity:", data['severity'], sev_color)
        self._add_kv(self.frm_overview, "Rule:", data['rule_desc'])
        self._add_kv(self.frm_overview, "State:", data['state'])
        self._add_kv(self.frm_overview, "Assigned To:", data['assignee'])
        self._add_kv(self.frm_overview, "Created:", data['timestamp'])

        self._add_kv(self.frm_network, "Source:", data['src_ip'])
        self._add_kv(self.frm_network, "Destination:", data['dst_ip'])
        self._add_kv(self.frm_network, "Service/Action:", f"{data['service']} / {data['action']}")

        txt = ctk.CTkTextbox(self.frm_raw, height=60, font=("Courier", 11))
        txt.pack(fill="x")
        txt.insert("1.0", data['raw_event'])
        txt.configure(state="disabled")

        self._render_iocs(data['iocs'])

        for event in reversed(data['timeline']): 
            ctk.CTkLabel(self.frm_timeline, text=event, text_color=COLORS["text_muted"], justify="left", anchor="w").pack(fill="x", pady=1)

        for t in [self.txt_notes, self.txt_findings, self.txt_evidence]: t.configure(state="normal")
        self.txt_notes.delete("1.0", tk.END); self.txt_notes.insert("1.0", data['notes'])
        self.txt_findings.delete("1.0", tk.END); self.txt_findings.insert("1.0", data['findings'])
        self.txt_evidence.delete("1.0", tk.END); self.txt_evidence.insert("1.0", data['evidence'])

        for btn in [self.btn_primary, self.btn_save, self.btn_close, self.btn_escalate]: 
            btn.pack_forget()
            
        if data["state"] in ["CLOSED", "ESCALATED"]:
            self._disable_workspace()
            ctk.CTkLabel(self.frm_actions, text=f"Alert is {data['state']}. View Only.", font=("Segoe UI", 14, "bold"), text_color=COLORS["critical"]).pack(side="left")
            
        elif data["assignee"] == "Unassigned":
            self._disable_workspace()
            self.btn_primary.configure(text="Assign to Me", command=self.assign_self)
            self.btn_primary.pack(side="left", padx=5)
            
        elif data["assignee"] != self.service.current_user:
            self._disable_workspace()
            ctk.CTkLabel(self.frm_actions, text=f"Assigned to {data['assignee']}. View Only.", font=("Segoe UI", 14, "bold"), text_color=COLORS["high"]).pack(side="left")
            
        else:
            if data["state"] == "ASSIGNED":
                self.btn_primary.configure(text="Start Investigation", command=self.start_inv)
                self.btn_primary.pack(side="left", padx=5)
            
            self.btn_save.pack(side="left", padx=5)
            self.btn_close.pack(side="left", padx=5)
            self.btn_escalate.pack(side="right", padx=5)

    def _render_iocs(self, ioc_list):
        """
        Draw the IOC rows. While any IOC is waiting on the
        enrichment worker, re-check every few seconds so the row
        flips to "Cached Intelligence Available" by itself.
        Only this section is refreshed, so unsaved text in the
        notes/findings/evidence boxes is never overwritten.
        """

        if self._ioc_poll_job is not None:
            try:
                self.after_cancel(self._ioc_poll_job)
            except tk.TclError:
                pass
            self._ioc_poll_job = None

        for w in self.frm_iocs.winfo_children():
            w.destroy()

        pending = False

        for ioc_val in ioc_list:
            row = ctk.CTkFrame(self.frm_iocs, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ioc_info = self.service.get_ioc_intelligence(ioc_val)
            
            ctk.CTkLabel(row, text=ioc_val, font=("Segoe UI", 12, "bold")).pack(side="left")
            
            status = ioc_info["status"]
            if status == "Cached Intelligence Available":
                ctk.CTkLabel(row, text="Cached Intelligence Available", text_color=COLORS["low"], font=("Segoe UI", 11, "italic")).pack(side="left", padx=15)
                btn = ctk.CTkButton(row, text="View Cached Intelligence", width=150, height=24, fg_color=COLORS["bg_card"], command=lambda v=ioc_val, i=ioc_info: IOCDetailDialog(self, v, i))
                btn.pack(side="right")
            elif status == "Requested":
                pending = True
                ctk.CTkLabel(row, text="⏳ Enrichment in progress...", text_color=COLORS["high"]).pack(side="left", padx=15)
            else:
                btn = ctk.CTkButton(row, text="Request Enrichment", width=140, height=24, fg_color=COLORS["accent"], command=lambda v=ioc_val: self.trigger_enrichment(v))
                btn.pack(side="right")

        if pending:
            watched = self.alert_id
            self._ioc_poll_job = self.after(
                3000,
                lambda: self._poll_iocs(watched)
            )

    def _poll_iocs(self, watched_alert_id):
        self._ioc_poll_job = None

        if (
            not self.winfo_exists()
            or self.alert_id != watched_alert_id
        ):
            return

        try:
            data = self.service.get_alert(watched_alert_id)
        except (ValueError, RuntimeError):
            return

        self._render_iocs(data["iocs"])

        for w in self.frm_timeline.winfo_children():
            w.destroy()

        for event in reversed(data["timeline"]):
            ctk.CTkLabel(
                self.frm_timeline,
                text=event,
                text_color=COLORS["text_muted"],
                justify="left",
                anchor="w"
            ).pack(fill="x", pady=1)

    def _disable_workspace(self):
        for t in [self.txt_notes, self.txt_findings, self.txt_evidence]: t.configure(state="disabled")

    def _add_kv(self, parent, key, value, val_color=None):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", pady=1)
        ctk.CTkLabel(f, text=key, width=90, anchor="w", text_color=COLORS["text_muted"]).pack(side="left")
        ctk.CTkLabel(f, text=value, anchor="w", text_color=val_color or COLORS["text_light"], font=("Segoe UI", 12, "bold" if val_color else "normal")).pack(side="left")

    def assign_self(self):
        try:
            self.service.claim_alert(
                self.alert_id,
                self.service.current_user
            )

        except (ValueError, PermissionError, RuntimeError) as exc:
            messagebox.showerror(
                "Unable to Claim Alert",
                str(exc),
                parent=self
            )
            return

        self.load_alert(self.alert_id)
        
    def start_inv(self):
        try:
            self.service.start_investigation(
                self.alert_id,
                self.service.current_user
            )

        except (ValueError, PermissionError, RuntimeError) as exc:
            messagebox.showerror(
                "Unable to Start Investigation",
                str(exc),
                parent=self
            )
            return

        self.load_alert(self.alert_id)

    def save_workspace(self):
        notes = self.txt_notes.get("1.0", tk.END).strip()
        findings = self.txt_findings.get("1.0", tk.END).strip()
        evidence = self.txt_evidence.get("1.0", tk.END).strip()
    
        try:
            self.service.save_investigation(
                self.alert_id,
                self.service.current_user,
                notes,
                findings,
                evidence
            )
    
        except (ValueError, PermissionError, RuntimeError) as exc:
            messagebox.showerror(
                "Unable to Save Investigation",
                str(exc),
                parent=self
            )
            return
    
        self.load_alert(self.alert_id)

    def trigger_enrichment(self, ioc_val):
        try:
            self.service.request_ioc_enrichment(
                ioc_val,
                self.service.current_user,
                self.alert_id
            )
    
        except (ValueError, PermissionError, RuntimeError) as exc:
            messagebox.showerror(
                "Unable to Request Enrichment",
                str(exc),
                parent=self
            )
            return
    
        self.load_alert(self.alert_id)

    def close_alert(self):
        CloseAlertDialog(
            self,
            self.alert_id,
            lambda disposition, notes: self.service.close_alert(
                self.alert_id,
                self.service.current_user,
                disposition,
                notes
            ),
            lambda: self.nav_callback("dashboard")
        )

    def escalate_alert(self):
        EscalateAlertDialog(
            self,
            self.alert_id,
            lambda data: self.service.escalate_alert(
                self.alert_id,
                self.service.current_user,
                data["summary"],
                data["evidence"],
                data["findings"],
                data["recommendation"]
            ),
            lambda: self.nav_callback("dashboard")
        )

class IOCIntelPage(ctk.CTkFrame):
    def __init__(self, parent, service):
        super().__init__(parent, fg_color="transparent")
        self.service = service
        ctk.CTkLabel(self, text="IOC Intelligence", font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.render_table())
        ctk.CTkEntry(self, textvariable=self.search_var, placeholder_text="Search IOCs...", width=300).pack(anchor="w", pady=(0,10))
        
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure(0, weight=2)
        self.content_frame.grid_columnconfigure(1, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        self.tree_frame = ctk.CTkFrame(self.content_frame, fg_color=COLORS["bg_card"])
        self.tree_frame.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        
        self.detail_frame = ctk.CTkFrame(self.content_frame, fg_color=COLORS["bg_card"])
        self.detail_frame.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(self.detail_frame, text="Select an IOC to view details", text_color=COLORS["text_muted"]).pack(expand=True)
        
        columns = ("IOC Value", "Type", "Status", "Reputation", "Source")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings")
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        for col in columns: self.tree.heading(col, text=col, anchor="w")
        
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        

    def load_data(self):
        self.render_table()

    def render_table(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        query = self.search_var.get().lower()
        
        count = 0
        for ioc_val, data in self.service.get_ioc_intelligence().items():
            if query and query not in ioc_val.lower() and query not in data["type"].lower(): continue
            self.tree.insert("", "end", values=(ioc_val, data["type"], data["status"], data["reputation"], data["source"]), tags=("evenrow" if count % 2 == 0 else "oddrow",))
            count += 1
            
        self.tree.tag_configure("evenrow", background="#2a2d2e")
        self.tree.tag_configure("oddrow", background=COLORS["bg_card"])

    def on_select(self, event):
        selected = self.tree.selection()
        if not selected: return
        ioc_val = self.tree.item(selected[0])['values'][0]
        data = self.service.get_ioc_intelligence(ioc_val)
        
        for w in self.detail_frame.winfo_children(): w.destroy()
        
        ctk.CTkLabel(self.detail_frame, text=ioc_val, font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=20, pady=(20,10))
        
        for k, v in data.items():
            row = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
            row.pack(fill="x", pady=4, padx=20)
            ctk.CTkLabel(row, text=k.title().replace("_", " ")+":", width=100, anchor="w", text_color=COLORS["text_muted"], font=("Segoe UI", 12, "bold")).pack(side="left")
            ctk.CTkLabel(row, text=v, anchor="w").pack(side="left")

        if data["status"] == "Cached Intelligence Available":
            btn = ctk.CTkButton(
                self.detail_frame,
                text="View Cached Intelligence",
                fg_color=COLORS["low"],
                command=lambda: IOCDetailDialog(
                    self,
                    ioc_val,
                    data
                )
            )
            btn.pack(pady=30)
        elif data["status"] == "Requested":
            btn = ctk.CTkButton(self.detail_frame, text="Enrichment in Progress...", fg_color=COLORS["high"], state="disabled")
            btn.pack(pady=30)
        else:
            btn = ctk.CTkButton(self.detail_frame, text="Request Enrichment", fg_color=COLORS["accent"], command=lambda: self.request_enrichment(ioc_val))
            btn.pack(pady=30)

    def request_enrichment(self, ioc_val):
        try:
            self.service.request_ioc_enrichment(
                ioc_val,
                self.service.current_user
            )
    
        except (ValueError, PermissionError, RuntimeError) as exc:
            messagebox.showerror(
                "Unable to Request Enrichment",
                str(exc),
                parent=self
            )
            return
    
        self.load_data()
        

class ReportsPage(ctk.CTkFrame):
    def __init__(self, parent, service):
        super().__init__(parent, fg_color="transparent")
        self.service = service
        ctk.CTkLabel(self, text="Escalation Reports", font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(fill="both", expand=True)
        self.content.grid_columnconfigure(0, weight=3)
        self.content.grid_columnconfigure(1, weight=2)
        self.content.grid_rowconfigure(0, weight=1)
        
        self.tree_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_card"])
        self.tree_frame.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        
        self.detail_frame = SmoothScrollFrame(self.content, fg_color=COLORS["bg_card"])
        self.detail_frame.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(self.detail_frame, text="Select a report to view details", text_color=COLORS["text_muted"]).pack(expand=True)
        
        columns = ("Report ID", "Alert ID", "Analyst", "Severity", "Status", "Updated")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings")
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        for col in columns: 
            self.tree.heading(col, text=col, anchor="w")
            self.tree.column(col, width=100)
            
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        
    def load_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
    
        reports = self.service.get_reports()
    
        for count, report in enumerate(reports):
            self.tree.insert(
                "",
                "end",
                values=(
                    report["id"],
                    report["alert_id"],
                    report["analyst_username"],
                    report["severity"],
                    report["status"],
                    report["updated_at"]
                ),
                tags=(
                    "evenrow" if count % 2 == 0 else "oddrow"
                )
            )
    
        self.tree.tag_configure(
            "evenrow",
            background="#2a2d2e"
        )
    
        self.tree.tag_configure(
            "oddrow",
            background=COLORS["bg_card"]
        )

    def on_select(self, event):
        selected = self.tree.selection()
        if not selected: return
        report_id = self.tree.item(selected[0])["values"][0]
        
        try:
            report = self.service.get_report(report_id)
        
        except ValueError as exc:
            messagebox.showerror(
                "Unable to Load Report",
                str(exc),
                parent=self
            )
            return
        
        for w in self.detail_frame.winfo_children(): w.destroy()
        
        ctk.CTkLabel(self.detail_frame, text=f"Report: {report['id']}", font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=10, pady=(10,5))
        
        def add_text_section(title, content):
            f = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
            f.pack(fill="x", padx=10, pady=5)
            ctk.CTkLabel(f, text=title, font=("Segoe UI", 12, "bold"), text_color=COLORS["text_muted"]).pack(anchor="w")
            txt = ctk.CTkTextbox(f, height=60)
            txt.pack(fill="x", pady=(2,0))
            txt.insert("1.0", content)
            txt.configure(state="disabled")
            
        add_text_section(
            "Executive Summary",
            report["summary"]
        )
        
        add_text_section(
            "Evidence",
            report["evidence"]
        )
        
        add_text_section(
            "Findings",
            report["findings"]
        )
        
        add_text_section(
            "Recommendation",
            report["recommendation"]
        )
        
        ctk.CTkLabel(
            self.detail_frame,
            text="Investigation Timeline",
            font=("Segoe UI", 12, "bold"),
            text_color=COLORS["text_muted"]
        ).pack(
            anchor="w",
            padx=10,
            pady=(10, 2)
        )
        
        tl_frame = ctk.CTkFrame(
            self.detail_frame,
            fg_color=COLORS["bg_panel"]
        )
        
        tl_frame.pack(
            fill="x",
            padx=10
        )
        
        audit_events = self.service.get_audit_log(
            alert_id=report["alert_id"]
        )
        
        for event in reversed(audit_events):
            timeline_text = (
                f"[{event['time']}] "
                f"{event['action']} | "
                f"{event['details']}"
            )
        
            ctk.CTkLabel(
                tl_frame,
                text=timeline_text,
                text_color=COLORS["text_light"],
                justify="left",
                anchor="w"
            ).pack(
                fill="x",
                padx=5,
                pady=2
            )
            
        btn_frame = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=20)
        ctk.CTkButton(btn_frame, text="Export PDF (Mock)", fg_color=COLORS["bg_card"], border_width=1).pack(side="right", padx=10)

class AnalystsPage(ctk.CTkFrame):
    def __init__(self, parent, service):
        super().__init__(parent, fg_color="transparent")
        self.service = service
        ctk.CTkLabel(self, text="SOC Team Workload", font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        self.tree_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=COLORS["bg_card"])
        self.tree_frame.pack(fill="both", expand=True)
        
        columns = ("Analyst Name", "Availability", "Active Assigned", "Investigating", "Closed", "Escalated")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings")
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        for col in columns: self.tree.heading(col, text=col, anchor="w")

    def load_data(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        for count, row in enumerate(self.service.get_analyst_stats()):
            self.tree.insert("", "end", values=row, tags=("evenrow" if count % 2 == 0 else "oddrow",))
            self.tree.tag_configure("evenrow", background="#2a2d2e")
            self.tree.tag_configure("oddrow", background=COLORS["bg_card"])

class TablePlaceholderPage(ctk.CTkFrame):
    def __init__(self, parent, title, columns, data_fetch_callback):
        super().__init__(parent, fg_color="transparent")
        self.data_fetch_callback = data_fetch_callback
        ctk.CTkLabel(self, text=title, font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=(0, 20))
        self.tree_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=COLORS["bg_card"])
        self.tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings")
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        for col in columns: self.tree.heading(col, text=col, anchor="w")

    def load_data(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        for count, row in enumerate(self.data_fetch_callback()):
            self.tree.insert("", "end", values=row, tags=("evenrow" if count % 2 == 0 else "oddrow",))
        self.tree.tag_configure("evenrow", background="#2a2d2e")
        self.tree.tag_configure("oddrow", background=COLORS["bg_card"])

# ==========================================
# MODULE 6: MAIN APPLICATION CONTROLLER
# ==========================================
class SOARApplication(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.configure_ttk_styles()

        self.service = SOARService(current_user="Analyst 01")
        self.service.initialize()

        # Fulfils analyst "Request Enrichment" clicks via VirusTotal.
        self.enrichment_worker = EnrichmentWorker(
            self.service.database
        )

        # Track the currently visible page so live refreshes only
        # touch queue pages and never overwrite an active investigation.
        self.current_page = None
        self._reader_restart_job = None
        self.wazuh_reader = WazuhReaderManager(
            on_status_change=self._request_reader_status_update,
            on_alert_created=self._request_new_alert_notification
        )

        self.title("SOC SOAR Console")
        self.geometry("1400x900")
        self.minsize(1200, 800)
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.setup_sidebar()
        self.setup_main_area()
        self.init_pages()
        self.navigate("dashboard")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.enrichment_worker.start()
        self._start_wazuh_reader()

    def configure_ttk_styles(self):
        style = ttk.Style(self)
    
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
    
        style.configure(
            "Treeview",
            background=COLORS["bg_card"],
            foreground=COLORS["text_light"],
            fieldbackground=COLORS["bg_card"],
            rowheight=35,
            borderwidth=0
        )
    
        style.map(
            "Treeview",
            background=[
                ("selected", COLORS["accent"])
            ],
            foreground=[
                ("selected", "#ffffff")
            ]
        )
    
        style.configure(
            "Treeview.Heading",
            background="#151718",
            foreground="#ffffff",
            relief="flat",
            font=("Segoe UI", 12, "bold")
        )
    
    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=COLORS["bg_main"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(10, weight=1) 
        
        ctk.CTkLabel(self.sidebar, text="🛡️ SOAR Platform", font=("Segoe UI", 22, "bold")).grid(row=0, column=0, padx=20, pady=(30, 40))
        
        nav_items = [
            ("Dashboard / Queue", "dashboard"),
            ("My Alerts", "my_alerts"),
            ("Reports", "reports"),
            ("IOC Intelligence", "ioc_intel"),
            ("Analysts", "analysts"),
            ("Audit Log", "audit")
        ]
        
        for i, (label, target) in enumerate(nav_items, start=1):
            btn = ctk.CTkButton(self.sidebar, text=label, anchor="w", fg_color="transparent", font=("Segoe UI", 14), command=lambda t=target: self.navigate(t))
            btn.grid(row=i, column=0, sticky="ew", padx=10, pady=5)
            
        status_frame = ctk.CTkFrame(self.sidebar, fg_color=COLORS["bg_card"], corner_radius=8)
        status_frame.grid(row=11, column=0, sticky="ew", padx=10, pady=20)
        
        ctk.CTkLabel(status_frame, text=f"👤 {self.service.current_user}", font=("Segoe UI", 14, "bold")).pack(pady=(10,0))
        current_analyst = self.service.get_analyst(
            self.service.current_user
        )
        
        self.status_var = ctk.StringVar(
            value=current_analyst["availability"]
        )
        
        sw = ctk.CTkSwitch(
            status_frame,
            text="Available",
            variable=self.status_var,
            onvalue="Available",
            offvalue="Away / Offline",
            command=self.change_availability
        )        
        
        sw.pack(pady=10)

        self.reader_status_label = ctk.CTkLabel(
            status_frame,
            text="Wazuh Reader: Starting",
            font=("Segoe UI", 10),
            text_color=COLORS["text_muted"]
        )
        self.reader_status_label.pack(
            pady=(0, 10)
        )

    def setup_main_area(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

    def init_pages(self):
        self.pages = {
            "dashboard": DashboardPage(self.main_container, self.navigate, self.service),
            "my_alerts": MyAlertsPage(self.main_container, self.navigate, self.service),
            "investigation": InvestigationPage(self.main_container, self.navigate, self, self.service),
            "ioc_intel": IOCIntelPage(self.main_container, self.service),
            "reports": ReportsPage(self.main_container, self.service),
            "analysts": AnalystsPage(self.main_container, self.service),
            "audit": TablePlaceholderPage(
                self.main_container,
                "System Audit Log",
                ("Time", "User", "Action", "Alert ID", "Details"),
                lambda: [
                    (
                        event["time"],
                        event["user"],
                        event["action"],
                        event["alert_id"],
                        event["details"]
                    )
                    for event in self.service.get_audit_log()
                ]
            )
        }
        for page in self.pages.values(): page.grid(row=0, column=0, sticky="nsew")

    def navigate(self, page_name, **kwargs):
        for page in self.pages.values():
            page.grid_remove()

        self.current_page = page_name
        page = self.pages[page_name]
        
        if page_name == "investigation" and "alert_id" in kwargs:
            page.load_alert(kwargs["alert_id"])
        else:
            page.load_data()
            
        page.grid()

    def _request_reader_status_update(self, status):
        """Queue a reader-status update on the Tkinter UI thread."""

        try:
            self.after(0, self._set_reader_status, status)
        except tk.TclError:
            pass

    def _set_reader_status(self, status):
        """Update the sidebar reader status safely on the UI thread."""

        if not hasattr(self, "reader_status_label"):
            return

        display_status = status
        if status.startswith("Error"):
            display_status = "Wazuh Reader: Error"
        else:
            display_status = f"Wazuh Reader: {status}"

        self.reader_status_label.configure(
            text=display_status
        )

    def _start_wazuh_reader(self):
        """Start the Wazuh reader and enable automatic recovery."""

        self.wazuh_reader.set_restart_callback(
            self._schedule_reader_restart
        )
        self.wazuh_reader.start()

    def _request_new_alert_notification(self):
        """Queue a non-invasive "new data" indicator on the Tk thread."""

        try:
            self.after(
                0,
                self._mark_new_alerts_available
            )
        except tk.TclError:
            pass

    def _mark_new_alerts_available(self):
        for page_name in ("dashboard", "my_alerts"):
            page = self.pages.get(page_name)
            if page is not None:
                page.mark_new_data_available()

    def _schedule_reader_restart(self, delay_seconds):
        """Schedule a reader restart on the Tkinter event loop."""

        if self._reader_restart_job is not None:
            return

        try:
            self._reader_restart_job = self.after(
                int(delay_seconds * 1000),
                self._restart_wazuh_reader
            )
        except tk.TclError:
            self._reader_restart_job = None

    def _restart_wazuh_reader(self):
        """Restart the reader after an unexpected process exit."""

        self._reader_restart_job = None

        if self.wazuh_reader.stop_requested:
            return

        self._set_reader_status("Restarting")
        self.wazuh_reader.start()

    def _on_close(self):
        """Stop background activities and close the application cleanly."""

        if self._reader_restart_job is not None:
            try:
                self.after_cancel(self._reader_restart_job)
            except tk.TclError:
                pass
            self._reader_restart_job = None

        self.wazuh_reader.stop()
        self.enrichment_worker.stop()
        self.destroy()

    def change_availability(self):
        try:
            self.service.set_analyst_availability(
                self.service.current_user,
                self.status_var.get()
            )
    
        except (ValueError, PermissionError, RuntimeError) as exc:
            messagebox.showerror(
                "Unable to Change Availability",
                str(exc),
                parent=self
            )
    
            analyst = self.service.get_analyst(
                self.service.current_user
            )
    
            self.status_var.set(
                analyst["availability"]
            )

if __name__ == "__main__":
    app = SOARApplication()
    app.mainloop()