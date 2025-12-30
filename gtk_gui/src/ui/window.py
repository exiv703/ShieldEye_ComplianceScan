
from gi.repository import Gtk, Adw, GLib
from pathlib import Path
import time
from datetime import datetime, timezone

from backend.core.scanner import Scanner
from backend.core.backend import analyze_scan_results
from backend.storage.database import ScanDatabase
from backend.utils.monitoring import get_health_checker

from .components import Sidebar
from .views import DashboardView, ScanView, HistoryView
from ..utils.styles import apply_css

class MainWindow(Adw.ApplicationWindow):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        db_path = Path.home() / ".shieldeye" / "scans.db"
        self.db = ScanDatabase(db_path)
        
        self.set_title("ShieldEye ComplianceScan")
        self.set_default_size(1600, 1200)
        self.set_show_menubar(False)
        
        apply_css(self)
        
        self._create_header_bar()
        
        self._build_ui()
        
        self._load_initial_data()

        GLib.timeout_add_seconds(30, self._refresh_periodic)
    
    def _create_header_bar(self):

        pass
    
    def _build_ui(self):
        """Build main UI layout."""

        root_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        header = Adw.HeaderBar()
        header.add_css_class("header-bar")

        self.window_title = Adw.WindowTitle()
        self.window_title.set_title("ShieldEye ComplianceScan")
        self.window_title.set_subtitle("Compliance Overview")
        header.set_title_widget(self.window_title)

        # Place the header bar at the top of the content area
        root_box.append(header)

        # Main horizontal layout below the header
        main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        root_box.append(main_box)

        self.set_content(root_box)

        self.sidebar = Sidebar(on_page_changed=self._on_page_changed)
        main_box.append(self.sidebar)
        
        self.content_stack = Gtk.Stack()
        self.content_stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.content_stack.set_hexpand(True)
        self.content_stack.set_vexpand(True)
        main_box.append(self.content_stack)
        
        self.dashboard_view = DashboardView(self.db, window=self)
        self.content_stack.add_named(self.dashboard_view, "dashboard")
        
        self.scan_view = ScanView(self.db, scanner_callback=self._run_scan, window=self)
        self.content_stack.add_named(self.scan_view, "scan")
        
        self.history_view = HistoryView(self.db)
        self.content_stack.add_named(self.history_view, "history")
        
        self.content_stack.set_visible_child_name("dashboard")
    
    def _on_page_changed(self, page_name):

        self.content_stack.set_visible_child_name(page_name)
        
        subtitles = {
            "dashboard": "Compliance Overview",
            "scan": "New Scan",
            "history": "Scan History"
        }
        self.window_title.set_subtitle(subtitles.get(page_name, ""))
        
        if page_name == "dashboard":
            self.dashboard_view.refresh_data()
        elif page_name == "history":
            self.history_view.refresh_data()
    
    def _load_initial_data(self):

        try:
            scanner_ok = True
            try:
                checker = get_health_checker()
                health = checker.perform_health_check()
                scanner_ok = bool(health.healthy)
            except Exception as e:
                print(f"Error checking scanner health: {e}")
                scanner_ok = False

            db_ok = True
            try:
                stats = self.db.get_statistics()

                total_scans = stats.get("total_scans", 0)
                total_critical = stats.get("total_critical_findings", 0)
                total_high = stats.get("total_high_findings", 0)
                total_medium = stats.get("total_medium_findings", 0)
                total_low = stats.get("total_low_findings", 0)

                threats_found = total_critical + total_high + total_medium + total_low

                self.sidebar.update_stats(total_scans, threats_found)
                self.dashboard_view.refresh_data()
            except Exception as e:
                print(f"Error loading statistics from database: {e}")
                db_ok = False

            self.sidebar.update_system_status(scanner_ok, db_ok)
        except Exception as e:
            print(f"Error loading initial data: {e}")
    
    def _refresh_periodic(self) -> bool:

        try:
            self._load_initial_data()
        except Exception as e:
            print(f"Error during periodic refresh: {e}")
        return True
    
    def _run_scan(self, url, standards, mode, progress_callback, complete_callback):

        scan_id = None
        try:
            progress_callback(0.1, "Initializing scanner...")
            
            start_ts = time.time()
            
            scanner = Scanner(url, standards, mode)
            
            progress_callback(0.3, "Scanning target...")
            
            results = scanner.run_scan()
            scan_id = results.get("scan_id", "unknown")
            
            progress_callback(0.7, "Analyzing results...")
            
            analysis = analyze_scan_results(results)
            summary = analysis.summary_counts
            
            self.db.create_scan(
                scan_id=scan_id,
                url=url,
                mode=mode,
                standards=standards
            )
            duration = time.time() - start_ts
            end_time = datetime.now(timezone.utc).isoformat()

            self.db.update_scan(
                scan_id=scan_id,
                status="completed",
                end_time=end_time,
                duration=duration,
                score=analysis.score,
                counts=summary,
                pages_scanned=len(results.get("pages", {})),
                results=results,
            )

            for finding in analysis.findings:
                if finding.severity != "pass":
                    self.db.add_finding(
                        scan_id,
                        finding.severity,
                        finding.message,
                        finding.category,
                        finding.location,
                        finding.standards,
                    )
            
            progress_callback(1.0, "Scan completed!")
            
            GLib.idle_add(self._load_initial_data)
            GLib.idle_add(self.history_view.refresh_data)
            
            result_data = {
                "scan_id": scan_id,
                "url": url,
                "mode": mode,
                "standards": standards,
                "score": analysis.score,
                "summary": summary,
                "pages_scanned": len(results.get("pages", {})),
                "findings": [
                    {
                        "severity": f.severity,
                        "message": f.message,
                        "category": f.category,
                        "location": f.location,
                        "standards": f.standards or [],
                    }
                    for f in analysis.findings
                    if f.severity and f.severity.lower() != "pass"
                ],
            }

            complete_callback(True, "Scan completed successfully", result_data)
            
        except Exception as e:
            if scan_id:
                try:
                    self.db.update_scan(scan_id, status="failed", error_message=str(e))
                except Exception:
                    pass
            complete_callback(False, str(e), None)
