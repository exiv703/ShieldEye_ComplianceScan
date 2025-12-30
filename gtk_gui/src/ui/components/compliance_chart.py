
from gi.repository import Gtk
import cairo

class ComplianceChart(Gtk.DrawingArea):

    def __init__(self):
        super().__init__()
        self.set_size_request(700, 220)
        self.set_draw_func(self._draw_chart)
        
        self.data = [
            ("12-21", 15),
            ("12-22", 22),
            ("12-23", 18),
            ("12-24", 28),
            ("12-25", 25),
            ("12-26", 32),
            ("12-27", 38),
        ]
    
    def _draw_chart(self, area, cr, width, height, user_data=None):

        
        if not self.data:
            return
        
        margin = 40
        chart_width = width - 2 * margin
        chart_height = height - 2 * margin
        
        max_value = max(val for _, val in self.data) if self.data else 1
        
        bar_width = chart_width / len(self.data) * 0.6
        bar_spacing = chart_width / len(self.data)
        
        for i, (label, value) in enumerate(self.data):
            bar_height = (value / max_value) * chart_height
            
            x = margin + i * bar_spacing + (bar_spacing - bar_width) / 2
            y = height - margin - bar_height
            
            pattern = cairo.LinearGradient(x, y, x, y + bar_height)
            pattern.add_color_stop_rgb(0, 0.23, 0.51, 0.96)
            pattern.add_color_stop_rgb(1, 0.15, 0.39, 0.92)
            
            cr.set_source(pattern)
            radius = 6
            cr.new_sub_path()
            cr.arc(x + radius, y + radius, radius, math.pi, 3*math.pi/2)
            cr.arc(x + bar_width - radius, y + radius, radius, 3*math.pi/2, 0)
            cr.line_to(x + bar_width, y + bar_height)
            cr.line_to(x, y + bar_height)
            cr.close_path()
            cr.fill()
            
            cr.set_source_rgb(0.61, 0.64, 0.69)
            cr.select_font_face("Sans", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_MEDIUM)
            cr.set_font_size(12)
            
            text_extents = cr.text_extents(label)
            text_x = x + (bar_width - text_extents.width) / 2
            text_y = height - margin + 24
            
            cr.move_to(text_x, text_y)
            cr.show_text(label)
        
        cr.set_source_rgba(0.22, 0.25, 0.32, 0.5)
        cr.set_line_width(1)
        
        for i in range(5):
            y = margin + (chart_height / 4) * i
            cr.move_to(margin, y)
            cr.line_to(width - margin, y)
            cr.stroke()
    
    def update_data(self, data):

        self.data = data
        self.queue_draw()
