import os
os.environ['QT_API'] = 'pyqt6'
import sys
import qtawesome as qta
import random
import time
import re
import networkx as nx
import matplotlib.pyplot as plt
from urllib.parse import urlparse
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTextEdit, QGroupBox, QRadioButton,
                             QCheckBox, QTabWidget, QProgressBar, QGridLayout, QSizePolicy,
                             QGraphicsDropShadowEffect, QMessageBox, QGraphicsOpacityEffect, QFileDialog)
from PyQt6.QtGui import QFont, QFontDatabase, QColor, QLinearGradient, QBrush, QPalette
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QSequentialAnimationGroup, QThread, pyqtSignal

from config import Colors, Animations, Shadow, Text
from scanner import Scanner
from reporter import Reporter

class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        plt.style.use('dark_background')
        self.fig, self.ax = plt.subplots(figsize=(width, height), dpi=dpi)
        self.fig.patch.set_facecolor(Colors.BACKGROUND_START)
        self.ax.set_facecolor(Colors.BACKGROUND_START)
        super(MplCanvas, self).__init__(self.fig)

class Worker(QThread):

    finished = pyqtSignal(dict)
    log = pyqtSignal(str)

    def __init__(self, url, standards, mode):
        super().__init__()
        self.url = url
        self.standards = standards
        self.mode = mode

    def run(self):
        def log_handler(text):
            self.log.emit(text)

        scanner = Scanner(self.url, self.standards, self.mode)
        
        scanner.print = log_handler
        
        results = scanner.run_scan()
        self.finished.emit(results)


class ShieldEyeApp(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.scan_start_time = 0
        self.last_scan_results = None
        self.last_scan_duration = 0
        self.pulse_animation_group = QSequentialAnimationGroup(self)
        self.config_box_shadow = None
        self.binary_animation_timer = QTimer(self)
        self.binary_animation_timer.timeout.connect(self.animate_binary_grid)

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(Text.APP_TITLE)
        self.setGeometry(100, 100, 900, 800)

        palette = self.palette()
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0.0, QColor(Colors.BACKGROUND_START))
        gradient.setColorAt(1.0, QColor(Colors.BACKGROUND_END))
        palette.setBrush(QPalette.ColorRole.Window, QBrush(gradient))
        self.setPalette(palette)
        self.setAutoFillBackground(True)

        try:
            with open("style.qss", "r") as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            print("Warning: stylesheet 'style.qss' not found.")

        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        main_layout.addLayout(self.create_header())

        self.config_group_box = self.create_scan_config_group()
        main_layout.addWidget(self.config_group_box)

        self.results_group_box = self.create_results_group()
        main_layout.addWidget(self.results_group_box)

        main_layout.addLayout(self.create_action_buttons())

        main_layout.addLayout(self.create_footer())
        main_layout.addStretch(1)

        self.apply_shadows()
        
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.about_button.clicked.connect(self.show_about_dialog)
        self.clear_button.clicked.connect(self.clear_results)
        self.export_button.clicked.connect(self.export_report)
        self.url_input.textChanged.connect(self.validate_url_live)
        
        self.stop_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.start_pulsing_animation()
        self.add_initial_tips()

    def create_header(self):
        header_layout = QGridLayout()
        header_layout.setColumnStretch(1, 1)
        header_layout.setHorizontalSpacing(30)
        header_layout.setVerticalSpacing(0)

        text_block_widget = QWidget()
        text_block_layout = QVBoxLayout()
        text_block_layout.setContentsMargins(0, 0, 0, 0)
        text_block_layout.setSpacing(0)
        text_block_widget.setLayout(text_block_layout)

        title_label = QLabel("ShieldEye")
        title_label.setObjectName("title")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        subtitle_label = QLabel("See the threats before they see you")
        subtitle_label.setObjectName("subtitle")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        text_block_layout.addWidget(title_label)
        text_block_layout.addWidget(subtitle_label)
        
        header_layout.addWidget(text_block_widget, 0, 0, 1, 2)

        logo_art = """          _____
       .-'.  ':'-.
     .''::: .:    '.
    /   :::::'      \\
   ;.    ':' `       ;
   |       '..       |
   ; '      ::::.    ;
    \\       '::::   /
     '.      :::  .'
        '-.___'_.-'"""
        logo_label = QLabel(logo_art)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        num_repeats = 100
        line_pattern_1 = "|0|1" * num_repeats
        line_pattern_2 = "|1|0" * num_repeats
        
        binary_matrix = (
            f"{line_pattern_1}\n"
            f"{line_pattern_1}\n"
            f"{line_pattern_2}\n"
            f"{line_pattern_1}\n"
            f"{line_pattern_2}\n"
            f"{line_pattern_2}"
        )
        binary_label = QLabel(binary_matrix)
        binary_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        binary_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.binary_label = binary_label 
        self.original_binary_matrix = binary_matrix
        
        header_layout.addWidget(logo_label, 1, 0)
        header_layout.addWidget(binary_label, 1, 1)

        return header_layout

    def create_scan_config_group(self):
        config_box = QGroupBox("ShieldEye - Scan Configuration")
        layout = QGridLayout()
        config_box.setLayout(layout)

        url_label = QLabel("URL:")
        url_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        
        audit_label = QLabel("Audit Standards:")
        audit_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.check_rodo = QCheckBox("GDPR")
        self.check_pci = QCheckBox("PCI-DSS")
        self.check_iso = QCheckBox("ISO 27001")
        self.check_rodo.setChecked(True)
        audit_layout = QHBoxLayout()
        audit_layout.addWidget(self.check_rodo)
        audit_layout.addWidget(self.check_pci)
        audit_layout.addWidget(self.check_iso)
        audit_layout.addStretch(1)

        mode_label = QLabel("Scan Mode:")
        mode_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.mode_quick = QRadioButton("Quick/Safe")
        self.mode_aggressive = QRadioButton("Aggressive/Full")
        self.mode_quick.setChecked(True)
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(self.mode_quick)
        mode_layout.addWidget(self.mode_aggressive)
        mode_layout.addStretch(1)

        layout.addWidget(url_label, 0, 0)
        layout.addWidget(self.url_input, 0, 1)
        layout.addWidget(audit_label, 1, 0)
        layout.addLayout(audit_layout, 1, 1)
        layout.addWidget(mode_label, 2, 0)
        layout.addLayout(mode_layout, 2, 1)
        
        return config_box

    def create_action_buttons(self):
        actions_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Scan")
        self.start_button.setObjectName("startScanButton")
        self.start_button.setIcon(qta.icon('fa5s.play-circle', color=Colors.BUTTON_PRIMARY_TEXT, color_active=Colors.SUCCESS))
        self.start_button.setToolTip(Text.TOOLTIP_START)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(qta.icon('fa5s.stop-circle', color=Colors.TEXT_MAIN, color_active=Colors.DANGER))
        self.stop_button.setToolTip(Text.TOOLTIP_STOP)

        self.export_button = QPushButton("Export Report (PDF)")
        self.export_button.setIcon(qta.icon('fa5s.file-pdf', color=Colors.TEXT_MAIN, color_active=Colors.SUCCESS))
        self.export_button.setToolTip(Text.TOOLTIP_EXPORT)

        self.clear_button = QPushButton("Clear Results")
        self.clear_button.setIcon(qta.icon('fa5s.trash-alt', color=Colors.TEXT_MAIN, color_active=Colors.DANGER))
        self.clear_button.setToolTip(Text.TOOLTIP_CLEAR)

        self.about_button = QPushButton("About")
        self.about_button.setIcon(qta.icon('fa5s.info-circle', color=Colors.TEXT_MAIN, color_active=Colors.SUCCESS))
        self.about_button.setToolTip(Text.TOOLTIP_ABOUT)
        
        actions_layout.addWidget(self.start_button)
        actions_layout.addWidget(self.stop_button)
        actions_layout.addStretch(1)
        actions_layout.addWidget(self.export_button)
        actions_layout.addWidget(self.clear_button)
        actions_layout.addWidget(self.about_button)
        return actions_layout

    def apply_shadows(self):
        for widget in [self.config_group_box, self.results_group_box, self.start_button, 
                        self.stop_button, self.export_button, self.clear_button, self.about_button]:
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(Shadow.BLUR_RADIUS)
            shadow.setColor(Colors.SHADOW)
            shadow.setOffset(0, Shadow.OFFSET_Y)
            widget.setGraphicsEffect(shadow)
            if widget is self.start_button:
                self.start_button_shadow = shadow
            elif widget is self.config_group_box:
                self.config_box_shadow = shadow

    def start_pulsing_animation(self):
        if self.pulse_animation_group.state() == QPropertyAnimation.State.Running:
            return
            
        anim1 = QPropertyAnimation(self.start_button_shadow, b"blurRadius")
        anim1.setDuration(Animations.PULSE_DURATION)
        anim1.setStartValue(Animations.PULSE_BLUR_START)
        anim1.setEndValue(Animations.PULSE_BLUR_END)
        anim1.setEasingCurve(QEasingCurve.Type.InOutQuad)

        anim2 = QPropertyAnimation(self.start_button_shadow, b"blurRadius")
        anim2.setDuration(Animations.PULSE_DURATION)
        anim2.setStartValue(Animations.PULSE_BLUR_END)
        anim2.setEndValue(Animations.PULSE_BLUR_START)
        anim2.setEasingCurve(QEasingCurve.Type.InOutQuad)
        
        self.pulse_animation_group.clear()
        self.pulse_animation_group.addAnimation(anim1)
        self.pulse_animation_group.addAnimation(anim2)
        self.pulse_animation_group.setLoopCount(-1)
        self.pulse_animation_group.start()

    def stop_pulsing_animation(self):
        self.pulse_animation_group.stop()
        self.start_button_shadow.setBlurRadius(Shadow.BLUR_RADIUS)

    def _clear_ui_results(self, clear_logs=True):
        if clear_logs:
            self.tab_logs.clear()
        self.tab_violations.clear()
        self.tab_summary.clear()
        
        self.map_canvas.ax.clear()
        self.map_canvas.ax.text(0.5, 0.5, "Map will be generated after the scan.", 
                                ha='center', va='center', color=Colors.TEXT_MUTED)
        self.map_canvas.ax.axis('off')
        self.map_canvas.draw()
        
        self.last_scan_results = None
        self.last_scan_duration = 0
        self.export_button.setEnabled(False)

    def clear_results(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(Text.CLEAR_CONFIRM_TITLE)
        msg_box.setText(Text.CLEAR_CONFIRM_TEXT)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg_box.setDefaultButton(QMessageBox.StandardButton.No)
        msg_box.setIcon(QMessageBox.Icon.Question)
        
        msg_box.setStyleSheet(f"""
            QMessageBox {{ background-color: {Colors.BACKGROUND_END}; }} 
            QLabel {{ color: {Colors.TEXT_MAIN}; }} 
            QPushButton {{ min-width: 80px; }}
        """)

        if msg_box.exec() == QMessageBox.StandardButton.Yes:
            self._clear_ui_results()
            self.add_initial_tips()

    def show_about_dialog(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(Text.ABOUT_TITLE)
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(Text.get_about_content())
        msg_box.setIconPixmap(qta.icon('fa5s.shield-alt', color=Colors.SECONDARY_ACCENT).pixmap(64, 64))
        
        msg_box.setStyleSheet(f"""
            QMessageBox {{ background-color: {Colors.BACKGROUND_END}; }} 
            QLabel {{ color: {Colors.TEXT_MAIN}; }}
        """)
        msg_box.exec()

    def is_valid_url(self, url):
        regex = re.compile(
            r'^(?:http|ftp)s?://' 
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

    def validate_url_live(self, text):
        if not text or self.is_valid_url(text) or self.is_valid_url('https://' + text):
            self.url_input.setStyleSheet("")
        else:
            self.url_input.setStyleSheet(f"border: 1px solid {Colors.DANGER};")

    def start_scan(self):
        url = self.url_input.text()
        if not url or not (self.is_valid_url(url) or self.is_valid_url('https://' + url)):
            QMessageBox.warning(self, "Invalid URL", "Please enter a valid URL to scan.")
            return

        standards = []
        if self.check_rodo.isChecked(): standards.append("GDPR")
        if self.check_pci.isChecked(): standards.append("PCI-DSS")
        if self.check_iso.isChecked(): standards.append("ISO 27001")

        mode = "Aggressive/Full" if self.mode_aggressive.isChecked() else "Quick/Safe"

        self.stop_pulsing_animation()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.config_group_box.setEnabled(False)
        self.binary_animation_timer.start(Animations.GRID_ANIMATION_INTERVAL_MS)
        
        opacity_effect = QGraphicsOpacityEffect(self.config_group_box)
        self.config_group_box.setGraphicsEffect(opacity_effect)
        self.fade_out_animation = QPropertyAnimation(opacity_effect, b"opacity")
        self.fade_out_animation.setDuration(Animations.FADE_DURATION)
        self.fade_out_animation.setStartValue(1)
        self.fade_out_animation.setEndValue(0.3)
        self.fade_out_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.fade_out_animation.start()
        
        self.progress_bar.setRange(0, 0)
        self._clear_ui_results()
        self.tab_logs.append(">>> Scan started...")
        self.scan_start_time = time.time()
        
        self.worker = Worker(url, standards, mode)
        self.worker.log.connect(self.log_message)
        self.worker.finished.connect(self._finish_scan)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate() 
            self.worker.wait()

        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self._restore_config_box_state()
        self.binary_animation_timer.stop()
        self.binary_label.setText(self.original_binary_matrix) 
        
        self.tab_logs.append(">>> Scan aborted by user.")
        self.export_button.setEnabled(self.last_scan_results is not None)

    def _finish_scan(self, results):
        self.last_scan_results = results
        self.last_scan_duration = time.time() - self.scan_start_time
        self.export_button.setEnabled(True)
        
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self._restore_config_box_state()
        self.binary_animation_timer.stop()
        self.binary_label.setText(self.original_binary_matrix) 
        
        self.tab_logs.append(">>> Scan complete.")
        self.populate_results(results, self.last_scan_duration)
        self.highlight_results()
        self.worker = None

    def export_report(self):
        if not self.last_scan_results:
            QMessageBox.warning(self, "No Results", "There are no results to export. Please run a scan first.")
            return

        file_name, _ = QFileDialog.getSaveFileName(self, "Save Report As...", "ShieldEye_Report.pdf", "PDF Files (*.pdf)")

        if file_name:
            self.export_button.setText("Generating...")
            self.export_button.setEnabled(False)
            QApplication.processEvents() 

            reporter = Reporter(self.url_input.text(), self.last_scan_results, self.last_scan_duration)
            success, message = reporter.generate_pdf(file_name)

            self.export_button.setText("Export Report (PDF)")
            self.export_button.setEnabled(True)

            if success:
                QMessageBox.information(self, "Success", f"Report successfully saved to:\n{file_name}")
            else:
                QMessageBox.critical(self, "Error", f"Failed to generate PDF report.\n\n{message}")

    def _restore_config_box_state(self):
        opacity_effect = self.config_group_box.graphicsEffect()
        if not isinstance(opacity_effect, QGraphicsOpacityEffect):
             opacity_effect = QGraphicsOpacityEffect(self.config_group_box)
             self.config_group_box.setGraphicsEffect(opacity_effect)

        self.fade_in_animation = QPropertyAnimation(opacity_effect, b"opacity")
        self.fade_in_animation.setDuration(Animations.FADE_DURATION)
        self.fade_in_animation.setStartValue(0.3)
        self.fade_in_animation.setEndValue(1)
        self.fade_in_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.fade_in_animation.finished.connect(self._on_fade_in_finished)
        self.fade_in_animation.start()

    def _on_fade_in_finished(self):
        if self.config_group_box:
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(Shadow.BLUR_RADIUS)
            shadow.setColor(Colors.SHADOW)
            shadow.setOffset(0, Shadow.OFFSET_Y)
            self.config_box_shadow = shadow 
            self.config_group_box.setGraphicsEffect(self.config_box_shadow)
            self.config_group_box.setEnabled(True)
            self.start_pulsing_animation()

    def highlight_results(self):
        original_style = self.results_group_box.styleSheet()
        self.results_group_box.setStyleSheet(f"""
            QGroupBox {{
                border: 2px solid {Colors.SUCCESS};
                color: {Colors.PRIMARY_ACCENT};
                border-radius: 8px;
                margin-top: 1em;
                font-weight: bold;
                background-color: rgba(26, 32, 40, 0.5);
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }}
        """)
        
        QTimer.singleShot(1000, lambda: self.results_group_box.setStyleSheet(original_style))

    def log_message(self, message):
        self.tab_logs.append(f"- {message}")

    def populate_results(self, results_data, scan_duration):
        self.tab_violations.clear()
        self.tab_summary.clear()
        
        pages_results = results_data.get('pages', {})
        domain_findings = pages_results.get('domain_findings', {})
        site_graph = results_data.get('graph')
        
        all_findings = []
        if 'domain_findings' in pages_results:
            for category in pages_results['domain_findings'].values():
                all_findings.extend(category)

        for url, page_data in pages_results.items():
            if url == 'domain_findings':
                continue
            for category in page_data.values():
                all_findings.extend(category.get('findings', []))

        unique_findings_messages = set()
        final_findings = []
        for severity, message in all_findings:
            if message not in unique_findings_messages:
                unique_findings_messages.add(message)
                final_findings.append((severity, message))

        severity_map = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'pass': 4}
        final_findings.sort(key=lambda x: severity_map.get(x[0], 99))

        violations_html = ""
        summary_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for severity, message in final_findings:
            if severity != 'pass':
                summary_counts[severity.lower()] +=1
                color_val = getattr(Colors, severity.upper(), Colors.TEXT_MUTED)
                violations_html += f"<p style='color: {color_val};'><b>[{severity.upper()}]</b> {message}</p>"

        if not any(summary_counts.values()):
             violations_html = f"<h3 style='color: {Colors.SUCCESS};'>Congratulations!</h3>" \
                               f"<p style='color: {Colors.TEXT_MAIN};'>No security violations were found.</p>"

        self.tab_violations.setHtml(violations_html)

        audited_standards = results_data.get('standards', [])
        mode = results_data.get('mode', 'N/A')

        summary_html = Text.get_summary_html(scan_duration, self.url_input.text(), summary_counts, audited_standards, mode)
        self.tab_summary.setHtml(summary_html)

        if site_graph:
            self.draw_site_map(results_data)

    def draw_site_map(self, results_data):
        self.map_canvas.ax.clear()
        
        graph = results_data.get('graph')
        pages_results = results_data.get('pages', {})
        start_url = results_data.get('start_url')
        domain = urlparse(start_url).netloc
        domain_findings = pages_results.get('domain_findings', {})

        if not graph or not graph.nodes():
            self.map_canvas.ax.text(0.5, 0.5, "Could not generate map.", 
                                    ha='center', va='center', color=Colors.TEXT_MUTED)
            self.map_canvas.ax.axis('off')
            self.map_canvas.draw()
            return
            
        pos = nx.spring_layout(graph, seed=42, k=0.9)
        
        node_colors = []
        node_sizes = []
        labels = {}
        for node in graph.nodes():
            page_specific_findings = pages_results.get(node, {})
            
            all_node_findings = []
            if node == start_url:
                 all_node_findings.extend(f for cat in domain_findings.values() for f in cat if isinstance(f, tuple))

            for cat in page_specific_findings.values():
                all_node_findings.extend(cat.get('findings', []))
            
            has_critical = any(f[0] == 'critical' for f in all_node_findings)
            has_high = any(f[0] == 'high' for f in all_node_findings)
            
            if has_critical:
                node_colors.append(Colors.DANGER)
            elif has_high:
                node_colors.append(Colors.WARNING)
            else:
                node_colors.append(Colors.PRIMARY_ACCENT)

            if node == start_url:
                node_sizes.append(1500)
                labels[node] = domain
            else:
                node_sizes.append(700)
                path = urlparse(node).path
                if len(path) > 15:
                    path = path[:12] + '...'
                labels[node] = path if path else '/'


        nx.draw_networkx_nodes(graph, pos, ax=self.map_canvas.ax, node_size=node_sizes, node_color=node_colors)
        nx.draw_networkx_edges(graph, pos, ax=self.map_canvas.ax, width=1.0, alpha=0.5, edge_color=Colors.TEXT_MUTED, arrows=True)
        nx.draw_networkx_labels(graph, pos, labels, ax=self.map_canvas.ax, font_size=8, font_color=Colors.BUTTON_PRIMARY_TEXT, font_weight="bold")
        
        self.map_canvas.ax.axis('off')
        self.map_canvas.fig.tight_layout(pad=0)
        self.map_canvas.draw()

    def create_results_group(self):
        results_box = QGroupBox("ShieldEye - Scan Results")
        layout = QVBoxLayout()
        
        self.tabs = QTabWidget()
        self.tab_logs = QTextEdit()
        self.tab_logs.setReadOnly(True)
        self.tab_violations = QTextEdit()
        self.tab_violations.setReadOnly(True)
        self.tab_summary = QTextEdit()
        self.tab_summary.setReadOnly(True)
        
        self.map_canvas = MplCanvas(self, width=5, height=4, dpi=100)
        
        self.tabs.addTab(self.tab_logs, "Logs")
        self.tabs.addTab(self.tab_violations, "Violations")
        self.tabs.addTab(self.tab_summary, "Summary")
        self.tabs.addTab(self.map_canvas, "Site Map")

        layout.addWidget(self.tabs)
        results_box.setLayout(layout)
        return results_box

    def create_footer(self):
        footer_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        footer_layout.addWidget(self.progress_bar)
        return footer_layout

    def add_initial_tips(self):
        self.tab_logs.setHtml("""
            <p style='color: #CFD8DC;'>Welcome to ShieldEye! Here are some tips to get you started:</p>
            <p style='color: #00B894;'><b>TIP ✨:</b> Enter a full URL (e.g., https://example.com) for the most accurate scan.</p>
            <p style='color: #00B894;'><b>TIP ✨:</b> The 'Site Map' tab visualizes the scanned pages and their connections.</p>
            <p style='color: #00B894;'><b>TIP ✨:</b> After a scan, you can export a detailed PDF report using the 'Export Report' button.</p>
        """)

    def animate_binary_grid(self):
        current_text = self.binary_label.text()
        new_text = list(current_text)
        for i in range(len(new_text)):
            if new_text[i] in ('0', '1') and random.random() < 0.05:
                new_text[i] = '1' if new_text[i] == '0' else '0'
        self.binary_label.setText("".join(new_text))

def main():
    app = QApplication(sys.argv)
    
    font_id = QFontDatabase.addApplicationFont("fonts/CutiveMono-Regular.ttf")
    if font_id != -1:
        font_families = QFontDatabase.applicationFontFamilies(font_id)
        if font_families:
            monospace_font = QFont(font_families[0], 10)
            app.setFont(monospace_font)
    else:
        print("Warning: Could not load custom font. Falling back to default.")
            
    window = ShieldEyeApp()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main() 