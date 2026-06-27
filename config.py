
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
            <p style='color: {Colors.TEXT_MAIN};'>Version 1.0.0</p>
            <p style='color: {Colors.TEXT_MAIN};'>See the threats before they see you.</p>
            <br>
            <p style='color: {Colors.TEXT_MAIN};'>
            ShieldEye scans web targets for compliance gaps (GDPR, PCI-DSS,
            ISO 27001) and common vulnerabilities.
            </p>
            <p style='color: {Colors.TEXT_MUTED};'>© 2024 ShieldEye. All rights reserved.</p>
        """