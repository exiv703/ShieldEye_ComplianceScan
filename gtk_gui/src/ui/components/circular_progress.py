
from gi.repository import Gtk
import cairo
import math

class CircularProgress(Gtk.DrawingArea):

    def __init__(self, percentage=0, label=""):
        super().__init__()
        self.set_size_request(200, 200)
        self.set_draw_func(self._draw_progress)
        
        self.percentage = percentage
        self.label = label
    
    def _draw_progress(self, area, cr, width, height, user_data=None):

        center_x = width / 2
        center_y = height / 2
        radius = 75
        line_width = 10
        
        cr.set_antialias(cairo.ANTIALIAS_BEST)
        
        cr.set_source_rgb(0.2, 0.255, 0.333)
        cr.set_line_width(line_width)
        cr.set_line_cap(cairo.LINE_CAP_ROUND)
        cr.arc(center_x, center_y, radius, 0, 2 * math.pi)
        cr.stroke()
        
        if self.percentage > 0:
            angle = (self.percentage / 100) * 2 * math.pi
            
            if self.percentage >= 80:
                r, g, b = 0.204, 0.827, 0.6
            elif self.percentage >= 60:
                r, g, b = 0.376, 0.647, 0.98
            elif self.percentage >= 40:
                r, g, b = 0.984, 0.745, 0.141
            else:
                r, g, b = 0.973, 0.443, 0.443
            
            cr.set_source_rgba(0, 0, 0, 0.15)
            cr.set_line_width(line_width)
            cr.set_line_cap(cairo.LINE_CAP_ROUND)
            cr.arc(center_x, center_y + 1, radius, -math.pi/2, -math.pi/2 + angle)
            cr.stroke()
            
            cr.set_source_rgb(r, g, b)
            cr.set_line_width(line_width)
            cr.set_line_cap(cairo.LINE_CAP_ROUND)
            cr.arc(center_x, center_y, radius, -math.pi/2, -math.pi/2 + angle)
            cr.stroke()
        
        cr.set_source_rgb(0.973, 0.980, 0.988)
        cr.select_font_face("Sans", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
        cr.set_font_size(38)
        
        text = f"{int(self.percentage)}%"
        text_extents = cr.text_extents(text)
        text_x = center_x - text_extents.width / 2 - text_extents.x_bearing
        text_y = center_y - 4
        
        cr.move_to(text_x, text_y)
        cr.show_text(text)
        
        if self.label:
            cr.set_source_rgb(0.392, 0.455, 0.545)
            cr.select_font_face("Sans", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_NORMAL)
            cr.set_font_size(11)
            
            label_extents = cr.text_extents(self.label)
            label_x = center_x - label_extents.width / 2 - label_extents.x_bearing
            label_y = center_y + 22
            
            cr.move_to(label_x, label_y)
            cr.show_text(self.label)
    
    def update(self, percentage, label=None):

        self.percentage = percentage
        if label:
            self.label = label
        self.queue_draw()
