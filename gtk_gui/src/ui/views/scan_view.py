
from gi.repository import Gtk, GLib
import threading

class ScanView(Gtk.ScrolledWindow):

    def __init__(self, db, scanner_callback=None, window=None):
        super().__init__()
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        self.db = db
        self.scanner_callback = scanner_callback
        self.window = window
        self._build_ui()
    
    def _build_ui(self):

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        main_box.set_margin_top(32)
        main_box.set_margin_bottom(32)
        main_box.set_margin_start(32)
        main_box.set_margin_end(32)
        main_box.set_halign(Gtk.Align.CENTER)
        main_box.set_size_request(900, -1)
        
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title = Gtk.Label()
        title.set_markup('<span size="28000" weight="800">New Security Scan</span>')
        title.set_halign(Gtk.Align.START)
        title_box.append(title)
        
        subtitle = Gtk.Label(label="Configure and launch a new compliance scan")
        subtitle.set_halign(Gtk.Align.START)
        subtitle.add_css_class("dashboard-subtitle")
        title_box.append(subtitle)
        
        main_box.append(title_box)
        
        config_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        config_card.add_css_class("card")
        config_card.set_margin_top(8)
        
        url_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        url_label = Gtk.Label(label="TARGET URL")
        url_label.set_halign(Gtk.Align.START)
        url_label.add_css_class("metric-label")
        url_box.append(url_label)
        
        self.url_entry = Gtk.Entry()
        self.url_entry.set_placeholder_text("https://example.com")
        url_box.append(self.url_entry)
        config_card.append(url_box)
        
        standards_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        standards_label = Gtk.Label(label="COMPLIANCE STANDARDS")
        standards_label.set_halign(Gtk.Align.START)
        standards_label.add_css_class("metric-label")
        standards_box.append(standards_label)
        
        checks_box = Gtk.Box(spacing=24)
        
        self.gdpr_check = Gtk.CheckButton(label="GDPR")
        self.gdpr_check.set_active(True)
        checks_box.append(self.gdpr_check)
        
        self.pci_check = Gtk.CheckButton(label="PCI-DSS")
        checks_box.append(self.pci_check)
        
        self.iso_check = Gtk.CheckButton(label="ISO 27001")
        checks_box.append(self.iso_check)
        
        standards_box.append(checks_box)
        config_card.append(standards_box)
        
        mode_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        mode_label = Gtk.Label(label="SCAN MODE")
        mode_label.set_halign(Gtk.Align.START)
        mode_label.add_css_class("metric-label")
        mode_section.append(mode_label)
        
        mode_box = Gtk.Box(spacing=24)
        
        self.quick_radio = Gtk.CheckButton(label="Quick/Safe")
        self.quick_radio.set_active(True)
        mode_box.append(self.quick_radio)
        
        self.full_radio = Gtk.CheckButton(label="Aggressive/Full")
        self.full_radio.set_group(self.quick_radio)
        mode_box.append(self.full_radio)
        
        mode_section.append(mode_box)
        config_card.append(mode_section)
        
        main_box.append(config_card)
        
        button_box = Gtk.Box(spacing=16)
        button_box.set_margin_top(8)
        button_box.set_halign(Gtk.Align.END)
        
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.add_css_class("btn-secondary")
        cancel_btn.connect("clicked", self._on_cancel_clicked)
        button_box.append(cancel_btn)
        
        self.start_scan_btn = Gtk.Button(label=" Start Scan")
        self.start_scan_btn.set_icon_name("system-search-symbolic")
        self.start_scan_btn.add_css_class("btn-primary")
        self.start_scan_btn.connect("clicked", self._on_start_scan)
        button_box.append(self.start_scan_btn)
        
        main_box.append(button_box)
        
        self.progress_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.progress_box.add_css_class("card")
        self.progress_box.set_visible(False)
        
        progress_header = Gtk.Box(spacing=12)
        spinner = Gtk.Spinner()
        spinner.start()
        progress_header.append(spinner)
        
        progress_label = Gtk.Label(label="Scan in progress...")
        progress_label.set_halign(Gtk.Align.START)
        progress_label.set_markup("<b>Scan in progress...</b>")
        progress_header.append(progress_label)
        self.progress_box.append(progress_header)
        
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.progress_box.append(self.progress_bar)
        
        self.progress_text = Gtk.Label(label="Initializing...")
        self.progress_text.set_halign(Gtk.Align.START)
        self.progress_text.add_css_class("metric-label")
        self.progress_box.append(self.progress_text)
        
        main_box.append(self.progress_box)

        self.result_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.result_box.add_css_class("card")
        self.result_box.set_visible(False)

        result_header = Gtk.Label()
        result_header.set_markup("<b>Last Scan Results</b>")
        result_header.set_halign(Gtk.Align.START)
        self.result_box.append(result_header)

        self.result_summary_label = Gtk.Label(label="")
        self.result_summary_label.set_halign(Gtk.Align.START)
        self.result_summary_label.add_css_class("metric-label")
        self.result_box.append(self.result_summary_label)

        self.result_score_label = Gtk.Label(label="")
        self.result_score_label.set_halign(Gtk.Align.START)
        self.result_box.append(self.result_score_label)

        counts_box = Gtk.Box(spacing=16)

        self.critical_label = Gtk.Label(label="")
        self.critical_label.set_halign(Gtk.Align.START)
        self.critical_label.add_css_class("severity-critical")
        counts_box.append(self.critical_label)

        self.high_label = Gtk.Label(label="")
        self.high_label.set_halign(Gtk.Align.START)
        self.high_label.add_css_class("severity-medium")
        counts_box.append(self.high_label)

        self.medium_label = Gtk.Label(label="")
        self.medium_label.set_halign(Gtk.Align.START)
        self.medium_label.add_css_class("metric-label")
        counts_box.append(self.medium_label)

        self.low_label = Gtk.Label(label="")
        self.low_label.set_halign(Gtk.Align.START)
        self.low_label.add_css_class("metric-label")
        counts_box.append(self.low_label)

        self.result_box.append(counts_box)

        self.findings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.result_box.append(self.findings_box)

        main_box.append(self.result_box)
        
        self.set_child(main_box)
    
    def _on_cancel_clicked(self, button):

        self.url_entry.set_text("")
        self.gdpr_check.set_active(True)
        self.pci_check.set_active(False)
        self.iso_check.set_active(False)
        self.quick_radio.set_active(True)
        
        self.progress_box.set_visible(False)
        self.result_box.set_visible(False)
        
        if self.window and hasattr(self.window, '_on_page_changed'):
            self.window._on_page_changed('dashboard')
    
    def _on_start_scan(self, button):

        url = self.url_entry.get_text().strip()
        if not url:
            return
        
        standards = []
        if self.gdpr_check.get_active():
            standards.append("GDPR")
        if self.pci_check.get_active():
            standards.append("PCI-DSS")
        if self.iso_check.get_active():
            standards.append("ISO 27001")
        
        if not standards:
            standards = ["GDPR"]
        
        mode = "Quick/Safe" if self.quick_radio.get_active() else "Aggressive/Full"
        
        self.progress_box.set_visible(True)
        self.start_scan_btn.set_sensitive(False)
        
        if self.scanner_callback:
            thread = threading.Thread(
                target=self.scanner_callback,
                args=(url, standards, mode, self._on_scan_progress, self._on_scan_complete)
            )
            thread.daemon = True
            thread.start()
    
    def _on_scan_progress(self, progress, message):

        GLib.idle_add(self.progress_bar.set_fraction, progress)
        GLib.idle_add(self.progress_text.set_text, message)
    
    def _on_scan_complete(self, success, message, result_data):

        if success:
            GLib.idle_add(self.progress_text.set_text, "Scan completed!")
            GLib.idle_add(self.progress_bar.set_fraction, 1.0)
            GLib.idle_add(self._update_results, result_data)
            GLib.timeout_add_seconds(2, self._reset_ui)
        else:
            GLib.idle_add(self.progress_text.set_text, f"Error: {message}")
            GLib.idle_add(self.start_scan_btn.set_sensitive, True)
            GLib.idle_add(self._update_results, None)
    
    def _reset_ui(self):

        self.progress_box.set_visible(False)
        self.start_scan_btn.set_sensitive(True)
        self.url_entry.set_text("")
        return False

    def _update_results(self, result_data):

        if not result_data:
            self.result_box.set_visible(False)
            return False

        url = result_data.get("url", "")
        pages = result_data.get("pages_scanned", 0)
        standards = ", ".join(result_data.get("standards", [])) or "None"
        score = result_data.get("score", 0)
        summary = result_data.get("summary", {}) or {}

        self.result_summary_label.set_text(f"{url} • {pages} pages • Standards: {standards}")
        self.result_score_label.set_markup(
            f'<span size="18000" weight="700" color="#60A5FA">Score: {score}/100</span>'
        )

        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)

        self.critical_label.set_text(f"Critical: {critical}")
        self.high_label.set_text(f"High: {high}")
        self.medium_label.set_text(f"Medium: {medium}")
        self.low_label.set_text(f"Low: {low}")

        max_iterations = 1000
        iterations = 0
        while iterations < max_iterations:
            child = self.findings_box.get_first_child()
            if child is None:
                break
            self.findings_box.remove(child)
            iterations += 1

        findings = result_data.get("findings", []) or []

        if findings:
            header = Gtk.Label()
            header.set_markup('<span size="12000" weight="600">Detected issues</span>')
            header.set_halign(Gtk.Align.START)
            self.findings_box.append(header)

            for f in findings:
                row = Gtk.Box(spacing=10)
                row.add_css_class("finding-row")

                sev = (f.get("severity") or "").lower()
                sev_label = Gtk.Label()
                sev_text = sev.upper() or "INFO"
                if sev == "critical":
                    sev_label.add_css_class("severity-critical")
                elif sev == "high":
                    sev_label.add_css_class("severity-high")
                elif sev == "medium":
                    sev_label.add_css_class("severity-medium")
                elif sev == "low":
                    sev_label.add_css_class("severity-low")
                else:
                    sev_label.add_css_class("metric-label")
                sev_label.set_text(sev_text)
                row.append(sev_label)

                text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)

                msg = f.get("message") or ""
                msg_label = Gtk.Label()
                msg_label.set_halign(Gtk.Align.START)
                msg_label.set_wrap(True)
                msg_label.set_xalign(0.0)
                msg_label.set_markup(f'<span size="10500">{Gtk.utils.escape_markup(msg)}</span>' if hasattr(Gtk, 'utils') else msg)
                text_box.append(msg_label)

                meta_parts = []
                category = f.get("category")
                location = f.get("location")
                if category:
                    meta_parts.append(category)
                if location:
                    meta_parts.append(location)
                if meta_parts:
                    meta_label = Gtk.Label(label=" • ".join(meta_parts))
                    meta_label.set_halign(Gtk.Align.START)
                    meta_label.add_css_class("metric-label")
                    text_box.append(meta_label)

                row.append(text_box)
                self.findings_box.append(row)

        self.result_box.set_visible(True)
        return False
