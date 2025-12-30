
from PyQt6.QtGui import QColor

class Colors:
    BACKGROUND_START = "#121C23"
    BACKGROUND_END = "#1a2a33"
    PRIMARY_ACCENT = "#00B894"   
    SECONDARY_ACCENT = "#26C6DA"  
    TERTIARY_ACCENT = "#00ACC1"  
    SUBTITLE = "#B2DFDB"          
    TEXT_MAIN = "#CFD8DC"         
    TEXT_MUTED = "#78909C"        
    BUTTON_PRIMARY_TEXT = "#121C23" 
    DANGER = "#E57373"  
    WARNING = "#FFB74D"  
    SUCCESS = "#1DE9B6"   
    SHADOW = QColor(0, 184, 148, 35) 

class Animations:
    PULSE_DURATION = 1500
    FADE_DURATION = 300
    PULSE_BLUR_START = 25
    PULSE_BLUR_END = 40
    SCAN_DURATION_MS = 3000
    LOG_UPDATE_INTERVAL_MS = 200
    GRID_ANIMATION_INTERVAL_MS = 50

class Shadow:
    BLUR_RADIUS = 25
    OFFSET_Y = 5

class Text:
    APP_TITLE = "ShieldEye ComplianceScan"
    TOOLTIP_START = "Start a new scan"
    TOOLTIP_STOP = "Stop the current scan"
    TOOLTIP_EXPORT = "Export report to PDF file"
    TOOLTIP_CLEAR = "Clear all results"
    TOOLTIP_ABOUT = "About the application"
    ABOUT_TITLE = "About ShieldEye"
    CLEAR_CONFIRM_TITLE = "Confirmation"
    CLEAR_CONFIRM_TEXT = "Are you sure you want to clear all results?"

    @staticmethod
    def get_about_content():
        return f"""
            <h2 style='color: {Colors.SECONDARY_ACCENT};'>ShieldEye ComplianceScan</h2>
            <p style='color: {Colors.TEXT_MAIN};'>Version 1.0.1</p>
            <p style='color: {Colors.TEXT_MAIN};'>See the threats before they see you.</p>
            <br>
            <p style='color: {Colors.TEXT_MAIN};'>
            ShieldEye is a conceptual application designed for modern security auditing,
            providing tools for vulnerability scanning and compliance checking.
            </p>
            <p style='color: {Colors.TEXT_MUTED};'>© 2024 ShieldEye. All rights reserved.</p>
        """

    @staticmethod
    def get_summary_html(scan_duration_secs, url, summary_counts, standards_audited, mode):
        audited_str = ', '.join(standards_audited) if standards_audited else "None"
        
        return f"""
            <h3 style='color: {Colors.PRIMARY_ACCENT};'>Scan Summary</h3>
            <p style='color: {Colors.TEXT_MAIN};'><b>Target URL:</b> {url}</p>
            <p style='color: {Colors.TEXT_MAIN};'><b>Scan Mode:</b> {mode}</p>
            <p style='color: {Colors.TEXT_MAIN};'><b>Standards Audited:</b> {audited_str}</p>
            <br>
            <p style='color: {Colors.TEXT_MAIN};'>Scan completed in {scan_duration_secs:.2f} seconds.</p>
            <p style='color: {Colors.DANGER};'><b>Critical issues found: {summary_counts.get('critical', 0)}</b></p>
            <p style='color: {Colors.DANGER};'><b>High issues found: {summary_counts.get('high', 0)}</b></p>
            <p style='color: {Colors.WARNING};'><b>Medium issues found: {summary_counts.get('medium', 0)}</b></p>
            <p style='color: {Colors.TEXT_MUTED};'><b>Low issues found: {summary_counts.get('low', 0)}</b></p>
        """ 