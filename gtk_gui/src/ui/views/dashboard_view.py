
from gi.repository import Gtk, GLib
from datetime import datetime
from ..components import MetricCard, ScanItem, RiskBar, ComplianceChart, StandardsGrid

class DashboardView(Gtk.Box):

    def __init__(self, db, window=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.db = db
        self.window = window
        self.last_update = None
        self._build_ui()
    
    def _build_ui(self):

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=32)
        main_box.set_margin_top(40)
        main_box.set_margin_bottom(48)
        main_box.set_margin_start(40)
        main_box.set_margin_end(40)
        
        main_box.set_vexpand(True)
        main_box.set_valign(Gtk.Align.FILL)
        
        header_box = Gtk.Box(spacing=16)
        
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        title = Gtk.Label()
        title.set_markup('<span size="26000" weight="800" letter_spacing="-200">Compliance Overview</span>')
        title.set_halign(Gtk.Align.START)
        title_box.append(title)
        
        subtitle = Gtk.Label(label="Live scan results and compliance status")
        subtitle.set_halign(Gtk.Align.START)
        subtitle.add_css_class("dashboard-subtitle")
        title_box.append(subtitle)
        
        self.demo_indicator = Gtk.Label()
        self.demo_indicator.set_markup('<span size="9000" weight="600" color="#64748B">⚠ Demo Data Active</span>')
        self.demo_indicator.set_halign(Gtk.Align.START)
        self.demo_indicator.set_visible(False)
        title_box.append(self.demo_indicator)
        
        header_box.append(title_box)
        
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        header_box.append(spacer)
        
        refresh_btn = Gtk.Button(label="Refresh Data")
        refresh_btn.set_icon_name("view-refresh-symbolic")
        refresh_btn.add_css_class("btn-secondary")
        refresh_btn.connect("clicked", lambda b: self.refresh_data())
        header_box.append(refresh_btn)
        
        main_box.append(header_box)
        
        metrics_grid = Gtk.Grid()
        metrics_grid.set_column_spacing(14)
        metrics_grid.set_row_spacing(14)
        metrics_grid.set_column_homogeneous(True)
        
        self.total_scans_card = MetricCard("TOTAL SCANS", "2", "+0 change")
        metrics_grid.attach(self.total_scans_card, 0, 0, 1, 1)
        
        self.vulnerabilities_card = MetricCard("VULNERABILITIES", "0", "Requires attention")
        metrics_grid.attach(self.vulnerabilities_card, 1, 0, 1, 1)
        
        self.active_threats_card = MetricCard("ACTIVE THREATS", "0", "System secure")
        metrics_grid.attach(self.active_threats_card, 2, 0, 1, 1)
        
        self.risk_score_card = MetricCard("AVG RISK SCORE", "0.0", "Medium Risk")
        self.risk_score_card.set_info(
            "Average risk score from all completed scans.\n"
            "0–49: High Risk, 50–74: Medium Risk, 75–100: Low Risk."
        )
        metrics_grid.attach(self.risk_score_card, 3, 0, 1, 1)
        
        main_box.append(metrics_grid)
        
        row1 = Gtk.Grid()
        row1.set_column_spacing(18)
        row1.set_row_spacing(18)
        row1.set_column_homogeneous(True)
        row1.set_vexpand(True)
        
        compliance_card = self._create_compliance_card()
        row1.attach(compliance_card, 0, 0, 1, 1)
        
        standards_card = self._create_standards_card()
        row1.attach(standards_card, 1, 0, 1, 1)
        
        issues_card = self._create_issues_card()
        row1.attach(issues_card, 2, 0, 1, 1)
        
        main_box.append(row1)
        
        activity_card = self._create_activity_card()
        main_box.append(activity_card)

        # DashboardView is a Gtk.Box, so we append the main_box container
        # instead of using set_child (which is not available on Gtk.Box).
        self.append(main_box)

    def _create_compliance_card(self):

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("card")
        card.add_css_class("card-compliance")
        card.set_hexpand(True)
        card.set_vexpand(True)
        card.set_valign(Gtk.Align.FILL)
        
        header_box = Gtk.Box(spacing=6)
        header_box.set_halign(Gtk.Align.START)

        title = Gtk.Label()
        title.set_markup('<span size="14000" weight="700">Overall Compliance</span>')
        title.set_halign(Gtk.Align.START)
        header_box.append(title)

        info_button = Gtk.Button()
        info_button.add_css_class("flat")
        info_button.set_can_focus(False)
        info_button.set_valign(Gtk.Align.CENTER)

        info_label = Gtk.Label()
        info_label.set_markup('<span size="9000" color="#64748B">ⓘ</span>')
        info_button.set_child(info_label)

        popover = Gtk.Popover()
        popover.set_has_arrow(True)
        popover.set_parent(info_button)
        popover.set_autohide(True)

        pop_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        pop_box.set_margin_top(8)
        pop_box.set_margin_bottom(8)
        pop_box.set_margin_start(10)
        pop_box.set_margin_end(10)

        pop_text = Gtk.Label(label=(
            "Overall compliance percentage is based on the average risk score "
            "of all completed scans (0–100)."
        ))
        pop_text.set_wrap(True)
        pop_text.set_xalign(0.0)
        pop_box.append(pop_text)

        popover.set_child(pop_box)

        def _on_compliance_info_clicked(_button, this_popover=popover):
            this_popover.popup()

        info_button.connect("clicked", _on_compliance_info_clicked)
        header_box.append(info_button)

        card.append(header_box)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content_box.set_vexpand(True)
        content_box.set_valign(Gtk.Align.CENTER)
        content_box.set_margin_top(12)
        content_box.set_margin_bottom(12)
        
        self.compliance_metric_label = Gtk.Label()
        self.compliance_metric_label.set_markup('<span size="48000" weight="800" color="#3B82F6" letter_spacing="-800">76%</span>')
        self.compliance_metric_label.set_halign(Gtk.Align.START)
        content_box.append(self.compliance_metric_label)
        
        self.compliance_status_label = Gtk.Label()
        self.compliance_status_label.set_markup('<span size="11000" weight="500" color="#64748B">Compliant (76/100)</span>')
        self.compliance_status_label.set_halign(Gtk.Align.START)
        self.compliance_status_label.set_margin_bottom(8)
        content_box.append(self.compliance_status_label)
        
        self.compliance_progressbar = Gtk.ProgressBar()
        self.compliance_progressbar.set_fraction(0.76)
        self.compliance_progressbar.set_show_text(False)
        self.compliance_progressbar.set_hexpand(True)
        self.compliance_progressbar.add_css_class("compliance-progress")
        content_box.append(self.compliance_progressbar)
        
        self.compliance_updated_label = Gtk.Label()
        self.compliance_updated_label.set_markup('<span size="9000" color="#475569">Updated just now</span>')
        self.compliance_updated_label.set_halign(Gtk.Align.START)
        self.compliance_updated_label.set_margin_top(8)
        content_box.append(self.compliance_updated_label)
        
        card.append(content_box)
        
        return card
    
    def _create_standards_card(self):

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("card")
        card.add_css_class("card-standards")
        card.set_hexpand(True)
        card.set_vexpand(True)
        card.set_valign(Gtk.Align.FILL)
        
        header_box = Gtk.Box(spacing=6)
        header_box.set_halign(Gtk.Align.START)

        title = Gtk.Label()
        title.set_markup('<span size="14000" weight="700">Security Scores by Standard</span>')
        title.set_halign(Gtk.Align.START)
        header_box.append(title)

        info_button = Gtk.Button()
        info_button.add_css_class("flat")
        info_button.set_can_focus(False)
        info_button.set_valign(Gtk.Align.CENTER)

        info_label = Gtk.Label()
        info_label.set_markup('<span size="9000" color="#64748B">ⓘ</span>')
        info_button.set_child(info_label)

        popover = Gtk.Popover()
        popover.set_has_arrow(True)
        popover.set_parent(info_button)
        popover.set_autohide(True)

        pop_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        pop_box.set_margin_top(8)
        pop_box.set_margin_bottom(8)
        pop_box.set_margin_start(10)
        pop_box.set_margin_end(10)

        pop_text = Gtk.Label(label=(
            "These percentages show average security scores from scans tagged "
            "with each standard. They are NOT compliance certifications.\n\n"
            "For real compliance, consult with certified auditors."
        ))
        pop_text.set_wrap(True)
        pop_text.set_xalign(0.0)
        pop_box.append(pop_text)

        popover.set_child(pop_box)

        def _on_standards_info_clicked(_button, this_popover=popover):
            this_popover.popup()

        info_button.connect("clicked", _on_standards_info_clicked)
        header_box.append(info_button)

        card.append(header_box)
        
        self.standards_grid = StandardsGrid()
        self.standards_grid.set_vexpand(True)
        self.standards_grid.set_valign(Gtk.Align.CENTER)
        card.append(self.standards_grid)

        return card

    def _create_issues_card(self):

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("card")
        card.set_hexpand(True)
        card.set_vexpand(True)
        card.set_valign(Gtk.Align.FILL)

        header_box = Gtk.Box(spacing=6)
        header_box.set_halign(Gtk.Align.START)

        title = Gtk.Label()
        title.set_markup('<span size="14000" weight="700">Issues Summary</span>')
        title.set_halign(Gtk.Align.START)
        header_box.append(title)

        info_button = Gtk.Button()
        info_button.add_css_class("flat")
        info_button.set_can_focus(False)
        info_button.set_valign(Gtk.Align.CENTER)

        info_label = Gtk.Label()
        info_label.set_markup('<span size="9000" color="#64748B">ⓘ</span>')
        info_button.set_child(info_label)

        popover = Gtk.Popover()
        popover.set_has_arrow(True)
        popover.set_parent(info_button)
        popover.set_autohide(True)

        pop_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        pop_box.set_margin_top(8)
        pop_box.set_margin_bottom(8)
        pop_box.set_margin_start(10)
        pop_box.set_margin_end(10)

        pop_text = Gtk.Label(label=(
            "Critical = total critical findings. Warnings = sum of high, "
            "medium and low findings across all scans."
        ))
        pop_text.set_wrap(True)
        pop_text.set_xalign(0.0)
        pop_box.append(pop_text)

        popover.set_child(pop_box)

        def _on_issues_info_clicked(_button, this_popover=popover):
            this_popover.popup()

        info_button.connect("clicked", _on_issues_info_clicked)
        header_box.append(info_button)

        card.append(header_box)

        container_box = Gtk.Box(spacing=40)
        container_box.set_vexpand(True)
        container_box.set_valign(Gtk.Align.CENTER)
        container_box.set_halign(Gtk.Align.CENTER)

        critical_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        critical_box.set_halign(Gtk.Align.CENTER)

        self.critical_count_label = Gtk.Label()
        self.critical_count_label.set_markup('<span size="56000" weight="800" color="#DC2626" letter_spacing="-1000">0</span>')
        critical_box.append(self.critical_count_label)

        critical_label = Gtk.Label()
        critical_label.set_markup('<span size="10000" weight="600" color="#64748B" letter_spacing="200">CRITICAL</span>')
        critical_box.append(critical_label)

        critical_sub = Gtk.Label()
        critical_sub.set_markup('<span size="9000" color="#94A3B8">High impact issues</span>')
        critical_box.append(critical_sub)

        container_box.append(critical_box)

        separator = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        container_box.append(separator)

        other_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        other_box.set_halign(Gtk.Align.CENTER)

        self.warnings_count_label = Gtk.Label()
        self.warnings_count_label.set_markup('<span size="56000" weight="800" color="#D97706" letter_spacing="-1000">0</span>')
        other_box.append(self.warnings_count_label)

        other_label = Gtk.Label()
        other_label.set_markup('<span size="10000" weight="600" color="#64748B" letter_spacing="200">WARNINGS</span>')
        other_box.append(other_label)

        other_sub = Gtk.Label()
        other_sub.set_markup('<span size="9000" color="#94A3B8">Medium &amp; low impact</span>')
        other_box.append(other_sub)

        container_box.append(other_box)

        card.append(container_box)

        ratio_box = Gtk.Box(spacing=8)
        ratio_box.set_margin_top(4)
        ratio_box.set_margin_bottom(4)
        ratio_box.set_halign(Gtk.Align.FILL)

        ratio_label = Gtk.Label()
        ratio_label.set_markup('<span size="9000" color="#64748B">Critical share</span>')
        ratio_label.set_halign(Gtk.Align.START)
        ratio_box.append(ratio_label)

        self.issues_severity_bar = Gtk.ProgressBar()
        self.issues_severity_bar.set_hexpand(True)
        self.issues_severity_bar.set_show_text(True)
        self.issues_severity_bar.set_fraction(0.0)
        self.issues_severity_bar.add_css_class("issues-severity-bar")
        ratio_box.append(self.issues_severity_bar)

        card.append(ratio_box)

        return card

    def _create_activity_card(self):

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        card.add_css_class("card")
        card.add_css_class("card-activity")
        card.set_vexpand(False)

        header_box = Gtk.Box(spacing=12)
        title = Gtk.Label()
        title.set_markup('<span size="14000" weight="700">Recent Activity</span>')
        title.set_halign(Gtk.Align.START)
        header_box.append(title)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        header_box.append(spacer)

        view_all = Gtk.Button(label="View All")
        view_all.add_css_class("btn-secondary")
        view_all.set_has_frame(False)
        view_all.connect("clicked", self._on_view_all_clicked)
        header_box.append(view_all)

        card.append(header_box)

        self.activity_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.append(self.activity_box)

        return card
    
    
    def refresh_data(self):

        try:
            from datetime import datetime, timezone
            
            self.last_update = datetime.now(timezone.utc)
            
            stats = self.db.get_statistics()

            total_scans = stats.get("total_scans", 0)
            total_critical = stats.get("total_critical_findings", 0)
            total_high = stats.get("total_high_findings", 0)
            total_medium = stats.get("total_medium_findings", 0)
            total_low = stats.get("total_low_findings", 0)
            avg_score = stats.get("average_score", 0.0)
            completed = stats.get("completed_scans", 0)
            failed = stats.get("failed_scans", 0)

            self.total_scans_card.update(
                str(total_scans),
                f"{completed} completed • {failed} failed"
            )

            total_vulns = total_critical + total_high
            vuln_status = "Requires attention" if total_vulns > 0 else "No issues found"
            self.vulnerabilities_card.update(
                str(total_vulns),
                vuln_status
            )

            threat_status = "System at risk" if total_critical > 0 else "System secure"
            self.active_threats_card.update(
                str(total_critical),
                threat_status
            )

            risk_level = "High Risk" if avg_score < 50 else "Medium Risk" if avg_score < 75 else "Low Risk"
            
            score_color = "#60A5FA"
            
            self.risk_score_card.update(
                f"{avg_score:.1f}",
                risk_level,
                color=score_color
            )

            compliance_percentage = int(avg_score) if total_scans > 0 else 0
            
            if compliance_percentage >= 75:
                status_text = "Compliant"
            elif compliance_percentage >= 50:
                status_text = "Partial"
            else:
                status_text = "Critical"
            
            self.compliance_metric_label.set_markup(
                f'<span size="48000" weight="800" color="#3B82F6" letter_spacing="-800">{compliance_percentage}%</span>'
            )
            self.compliance_status_label.set_markup(
                f'<span size="11000" weight="500" color="#64748B">{status_text} ({compliance_percentage}/100)</span>'
            )
            self.compliance_progressbar.set_fraction(compliance_percentage / 100.0)
            
            self.compliance_updated_label.set_markup(
                '<span size="9000" color="#475569">Updated just now</span>'
            )

            self.critical_count_label.set_markup(
                f'<span size="56000" weight="800" color="#DC2626" letter_spacing="-1000">{total_critical}</span>'
            )

            warnings_count = total_high + total_medium + total_low
            self.warnings_count_label.set_markup(
                f'<span size="56000" weight="800" color="#D97706" letter_spacing="-1000">{warnings_count}</span>'
            )

            total_issues = total_critical + warnings_count
            if total_issues > 0:
                critical_share = total_critical / total_issues
                self.issues_severity_bar.set_fraction(critical_share)
                self.issues_severity_bar.set_text(f"{int(critical_share * 100)}% critical")
            else:
                self.issues_severity_bar.set_fraction(0.0)
                self.issues_severity_bar.set_text("No issues")

            self._update_recent_activity()

            self._update_standards_coverage()

        except Exception as e:
            print(f"Error refreshing dashboard: {e}")
            import traceback
            traceback.print_exc()

    def _on_view_all_clicked(self, button):

        if self.window and hasattr(self.window, '_on_page_changed'):
            self.window._on_page_changed('history')
    
    def _update_recent_activity(self):

        try:
            max_iterations = 1000
            iterations = 0
            while iterations < max_iterations:
                child = self.activity_box.get_first_child()
                if child is None:
                    break
                self.activity_box.remove(child)
                iterations += 1

            recent_scans = self.db.get_scans(limit=3)

            if not recent_scans:
                empty_label = Gtk.Label()
                empty_label.set_markup('<span size="11000" color="#64748B">No recent activity</span>')
                self.activity_box.append(empty_label)
                return
            
            has_demo_data = any(scan.get('scan_id', '').startswith('demo-') for scan in recent_scans)
            if has_demo_data and hasattr(self, 'demo_indicator'):
                self.demo_indicator.set_visible(True)
            elif hasattr(self, 'demo_indicator'):
                self.demo_indicator.set_visible(False)

            for scan in recent_scans:
                status = scan.get("status", "unknown")
                if status == "completed":
                    icon = "●"
                    icon_color = "#10B981"
                    status_badge = "SUCCESS"
                    badge_color = "#10B981"
                elif status == "failed":
                    icon = "●"
                    icon_color = "#EF4444"
                    status_badge = "FAILED"
                    badge_color = "#EF4444"
                else:
                    icon = "●"
                    icon_color = "#F59E0B"
                    status_badge = "IN PROGRESS"
                    badge_color = "#F59E0B"

                title = f"Scan {status}"
                url = scan.get("url", "Unknown")
                pages = scan.get("pages_scanned", 0)
                desc = f"{url} • {pages} pages scanned"

                start_time = scan.get("start_time", "")
                if start_time:
                    try:
                        from datetime import datetime, timezone
                        dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        diff = now - dt
                        
                        if diff.total_seconds() < 60:
                            time_str = "Just now"
                        elif diff.total_seconds() < 3600:
                            mins = int(diff.total_seconds() / 60)
                            time_str = f"{mins} min ago"
                        elif diff.total_seconds() < 86400:
                            hours = int(diff.total_seconds() / 3600)
                            time_str = f"{hours}h ago"
                        else:
                            days = int(diff.total_seconds() / 86400)
                            time_str = f"{days}d ago"
                    except Exception as e:
                        print(f"Time parse error: {e}, start_time={start_time}")
                        time_str = "Recent"
                else:
                    time_str = "Recent"

                item = self._create_activity_item(icon, icon_color, title, desc, time_str, status_badge, badge_color)
                self.activity_box.append(item)

        except Exception as e:
            print(f"Error updating recent activity: {e}")
            import traceback
            traceback.print_exc()

    def _create_activity_item(self, icon, icon_color, title, desc, time, status_badge, badge_color):

        item = Gtk.Box(spacing=14)
        item.set_margin_top(4)
        item.set_margin_bottom(4)

        icon_label = Gtk.Label(label=icon)
        icon_label.set_markup(f'<span size="14000" weight="700" color="{icon_color}">{icon}</span>')
        item.append(icon_label)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        
        title_box = Gtk.Box(spacing=8)
        title_label = Gtk.Label(label=title)
        title_label.set_halign(Gtk.Align.START)
        title_label.set_markup(f'<span size="11000" weight="600">{title}</span>')
        title_box.append(title_label)
        
        badge = Gtk.Label()
        badge.set_markup(f'<span size="8500" weight="700" color="{badge_color}">{status_badge}</span>')
        badge.add_css_class("status-badge")
        title_box.append(badge)
        
        info_box.append(title_box)

        desc_label = Gtk.Label(label=desc)
        desc_label.set_halign(Gtk.Align.START)
        desc_label.set_markup(f'<span size="10000" color="#64748B">{desc}</span>')
        desc_label.set_ellipsize(3)
        desc_label.set_max_width_chars(50)
        info_box.append(desc_label)
        item.append(info_box)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        item.append(spacer)

        time_label = Gtk.Label(label=time)
        time_label.set_markup(f'<span size="10000" color="#64748B">{time}</span>')
        item.append(time_label)

        return item

    def _update_standards_coverage(self):

        try:
            scans = self.db.get_scans(limit=100)

            if not scans:
                return

            standards_data = {
                "ISO 27001": {"icon": "▲", "desc": "Info Security", "scores": []},
                "GDPR": {"icon": "■", "desc": "Data Protection", "scores": []},
                "HIPAA": {"icon": "◆", "desc": "Healthcare Data", "scores": []},
                "PCI-DSS": {"icon": "●", "desc": "Payment Security", "scores": []}
            }

            for scan in scans:
                if scan.get("status") == "completed" and scan.get("score"):
                    score = scan.get("score", 0)
                    standards = scan.get("standards", "")
                    
                    if isinstance(standards, str):
                        try:
                            import json
                            standards = json.loads(standards)
                        except (json.JSONDecodeError, TypeError, ValueError):
                            standards = []
                    
                    if not standards:
                        for std in standards_data.values():
                            std["scores"].append(score)
                    else:
                        for std_name in standards:
                            if std_name in standards_data:
                                standards_data[std_name]["scores"].append(score)

            updated_standards = []
            for name, data in standards_data.items():
                if data["scores"]:
                    avg_score = sum(data["scores"]) / len(data["scores"])
                else:
                    avg_score = 0

                status = "compliant" if avg_score >= 80 else "partial" if avg_score >= 50 else "non-compliant"
                updated_standards.append((name, data["icon"], status, int(avg_score), data["desc"]))

            self.standards_grid.update_standards(updated_standards)

        except Exception as e:
            print(f"Error updating standards coverage: {e}")
            import traceback
            traceback.print_exc()
    
