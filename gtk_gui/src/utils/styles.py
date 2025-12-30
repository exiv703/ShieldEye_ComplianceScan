"""CSS Styles for the application."""

from gi.repository import Gtk, Gdk

CSS_STYLES = """
/* Modern Dark Theme Colors */
/* Palette:
   Background: #111827 (Gray 900)
   Surface: #1F2937 (Gray 800)
   Border: #374151 (Gray 700)
   Primary: #3B82F6 (Blue 500) -> #2563EB (Blue 600)
   Accent: #06B6D4 (Cyan 500)
   Text: #F9FAFB (Gray 50)
   Text Secondary: #9CA3AF (Gray 400)
*/

window {
    background-color: #0F172A;
    color: #F9FAFB;
    border-radius: 18px;
}

.sidebar {
    background-color: #0F172A;
    border-right: 1px solid #1E293B;
    min-width: 220px;
}

.card {
    background-color: #1E293B;
    border-radius: 12px;
    padding: 24px;
    border: 1px solid #334155;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
    transition: all 300ms cubic-bezier(0.4, 0, 0.2, 1);
}

.card:hover {
    border-color: #475569;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    transform: translateY(-2px);
}

/* Asymmetric card padding for organic feel */
.card-compliance {
    padding: 28px;
}

.card-standards {
    padding: 20px;
}

.card-activity {
    padding: 22px;
}

.sub-card {
    background-color: #262E3D; /* Slightly lighter than card */
    border-radius: 12px;
    padding: 8px;
    border: 1px solid #374151;
}

.metric-card {
    background: linear-gradient(145deg, #1E293B 0%, #0F172A 100%);
    border-radius: 12px;
    padding: 20px;
    border: 1px solid #334155;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
    transition: all 300ms cubic-bezier(0.4, 0, 0.2, 1);
}

.metric-card:hover {
    border-color: #60A5FA;
    box-shadow: 0 4px 16px rgba(96, 165, 250, 0.15);
    transform: translateY(-3px);
}

.metric-value {
    font-size: 36px;
    font-weight: 800;
    color: #60A5FA;
    margin-bottom: 4px;
    letter-spacing: -0.5px;
    font-variant-numeric: tabular-nums;
}

.metric-label {
    font-size: 13px;
    font-weight: 500;
    color: #9CA3AF;
    margin-top: 4px;
    opacity: 0.95;
}

.status-active { color: #34D399; } /* Emerald 400 */
.status-warning { color: #FBBF24; } /* Amber 400 */
.status-critical { color: #F87171; } /* Red 400 */

.btn-primary {
    background: linear-gradient(135deg, #3B82F6 0%, #2563EB 100%);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 10px 24px;
    font-weight: 600;
    box-shadow: 0 2px 4px rgba(37, 99, 235, 0.2);
    transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
}

.btn-primary:hover {
    background: linear-gradient(135deg, #60A5FA 0%, #3B82F6 100%);
    box-shadow: 0 6px 12px rgba(37, 99, 235, 0.4);
    transform: translateY(-2px);
}

.btn-primary:active {
    transform: translateY(0px);
    box-shadow: 0 2px 4px rgba(37, 99, 235, 0.3);
}

.btn-secondary {
    background-color: #374151;
    color: #E5E7EB;
    border: 1px solid #4B5563;
    border-radius: 10px;
    padding: 10px 20px;
    font-weight: 500;
    transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
}

.btn-secondary:hover {
    background-color: #4B5563;
    color: white;
    border-color: #6B7280;
    transform: translateY(-1px);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

.btn-secondary:active {
    transform: translateY(0px);
}

.sidebar-item {
    padding: 10px 14px;
    margin: 0;
    border-radius: 8px;
    background-color: transparent;
    border: none;
    color: #9CA3AF;
    font-weight: 500;
    transition: all 200ms cubic-bezier(0.4, 0, 0.2, 1);
    font-size: 13px;
}

.sidebar-item:hover {
    background-color: #101827;
    color: #F3F4F6;
    transform: translateX(3px);
}

.sidebar-item.active {
    background: linear-gradient(90deg, #3B82F6 0%, #2563EB 100%);
    color: white;
    box-shadow: 0 2px 8px rgba(37, 99, 235, 0.3);
}

.sidebar-subtitle {
    font-size: 11px;
    font-weight: 500;
    color: #9CA3AF;
    letter-spacing: 0.3px;
}

.sidebar-section-title {
    font-size: 9px;
    font-weight: 600;
    color: #94A3B8;
    letter-spacing: 0.5px;
}

.sidebar-stat-label {
    font-size: 11px;
    font-weight: 500;
    color: #94A3B8;
}

headerbar,
.header-bar {
    background-color: #0F172A;
    border-bottom: 1px solid #1E293B;
    min-height: 56px;
}

.chart-container {
    background-color: #1F2937;
    border-radius: 16px;
    padding: 20px;
}

entry {
    background-color: #374151;
    border: 1px solid #4B5563;
    border-radius: 8px;
    color: white;
    padding: 10px 14px;
    caret-color: #3B82F6;
}

entry selection {
    background-color: #3B82F6;
    color: white;
}

entry:focus {
    border-color: #60A5FA;
    background-color: #4B5563;
    box-shadow: 0 0 0 2px rgba(96, 165, 250, 0.2);
}

/* Badges */
.status-badge {
    background-color: rgba(59, 130, 246, 0.1);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 9px;
    font-weight: 700;
    border: 1px solid rgba(59, 130, 246, 0.2);
}

.severity-critical {
    background-color: rgba(239, 68, 68, 0.2);
    color: #F87171;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.severity-high {
    background-color: rgba(245, 158, 11, 0.2);
    color: #FBBF24;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

.severity-medium {
    background-color: rgba(251, 191, 36, 0.2);
    color: #FCD34D;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid rgba(251, 191, 36, 0.3);
}

.severity-low {
    background-color: rgba(16, 185, 129, 0.2);
    color: #34D399;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

/* Progress Bars */
progressbar {
    min-height: 6px;
    background-color: rgba(55, 65, 81, 0.5);
    border-radius: 3px;
}

progressbar progress {
    min-height: 6px;
    border-radius: 3px;
}

.progress-critical progressbar progress { 
    background: linear-gradient(90deg, #EF4444 0%, #DC2626 100%);
}

.progress-high progressbar progress { 
    background: linear-gradient(90deg, #F59E0B 0%, #D97706 100%);
}

.progress-medium progressbar progress { 
    background: linear-gradient(90deg, #F59E0B 0%, #EAB308 100%);
}

.progress-low progressbar progress { 
    background: linear-gradient(90deg, #10B981 0%, #059669 100%);
}

/* Compliance Progress Bar */
.compliance-progress {
    min-height: 6px;
}

.compliance-progress progress {
    background: linear-gradient(90deg, #3B82F6 0%, #2563EB 100%);
    min-height: 6px;
    border-radius: 3px;
}

/* Issues severity bar (critical share) */
.issues-severity-bar {
    min-height: 8px;
}

.issues-severity-bar progress {
    background: linear-gradient(90deg, #F97316 0%, #EF4444 100%); /* amber -> red */
    min-height: 8px;
    border-radius: 999px;
}

/* Standards Progress Bar - same style as compliance */
.standard-progress {
    min-height: 6px;
}

.standard-progress progress {
    background: linear-gradient(90deg, #3B82F6 0%, #2563EB 100%);
    min-height: 6px;
    border-radius: 3px;
}

/* Standards Grid Styling */
.standard-item {
    padding: 4px 0;
    border-radius: 8px;
    transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
}

.standard-item:hover {
    background-color: rgba(51, 65, 85, 0.5);
    transform: translateX(4px);
}

/* Scan Item in History View */
.scan-item {
    background-color: #1E293B;
    border-radius: 10px;
    padding: 16px 20px;
    border: 1px solid #334155;
    transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
}

.scan-item:hover {
    background-color: #243447;
    border-color: #475569;
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.standard-icon {
    color: #60A5FA;
    -gtk-icon-size: 18px;
    min-width: 18px;
    min-height: 18px;
}

.score-badge {
    padding: 4px 12px;
    border-radius: 8px;
    background-color: rgba(59, 130, 246, 0.15);
    border: 1px solid rgba(59, 130, 246, 0.3);
}

/* Dashboard Typography */
.dashboard-title {
    color: #F9FAFB;
    font-weight: 800;
    letter-spacing: -0.5px;
}

.dashboard-subtitle {
    color: #94A3B8;
    font-weight: 400;
    font-size: 14px;
}

.small-badge {
    font-size: 10px;
    padding: 2px 8px;
}

/* Loading and Skeleton States */
.skeleton {
    background: linear-gradient(90deg, #1E293B 25%, #2D3748 50%, #1E293B 75%);
    background-size: 200% 100%;
    animation: shimmer 1.5s ease-in-out infinite;
    border-radius: 4px;
}

@keyframes shimmer {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
}

.pulse {
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.fade-in {
    animation: fadeIn 400ms cubic-bezier(0.4, 0, 0.2, 1);
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

tooltip {
    background-color: #020617;
    color: #E2E8F0;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

/* Misc helpers */
.glow-on-hover:hover {
    box-shadow: 0 0 20px rgba(59, 130, 246, 0.3);
}

.empty-state {
    opacity: 0.6;
    transition: opacity 300ms ease;
}

.empty-state:hover {
    opacity: 0.8;
}

*:focus {
    outline: 2px solid #3B82F6;
    outline-offset: 2px;
}

*:disabled {
    opacity: 0.5;
}
"""

def apply_css(*_args, **_kwargs) -> None:
    css_provider = Gtk.CssProvider()
    css_provider.load_from_data(CSS_STYLES.encode())
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        css_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )
