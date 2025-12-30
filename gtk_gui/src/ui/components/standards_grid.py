
from gi.repository import Gtk

class StandardsGrid(Gtk.Box):

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)

        self.standards = [
            ("ISO 27001", "▲", "compliant", 87, "Info Security"),
            ("GDPR", "■", "compliant", 95, "Data Protection"),
            ("HIPAA", "◆", "non-compliant", 42, "Healthcare Data"),
            ("PCI-DSS", "●", "partial", 68, "Payment Security"),
        ]

        self._build_list()

    def _build_list(self):

        for name, icon, status, score, description in self.standards:
            row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            row.set_margin_top(4)
            row.set_margin_bottom(4)
            row.add_css_class("standard-item")

            header = Gtk.Box(spacing=12)

            label_box = Gtk.Box(spacing=12)
            
            icon_label = Gtk.Label()
            icon_label.set_markup(f'<span size="13000" weight="600" color="#60A5FA">{icon}</span>')
            icon_label.set_size_request(20, -1)
            label_box.append(icon_label)

            name_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            
            name_label = Gtk.Label()
            name_label.set_markup(f'<span size="11000" weight="600" color="#F1F5F9">{name}</span>')
            name_label.set_halign(Gtk.Align.START)
            name_box.append(name_label)
            
            desc_label = Gtk.Label()
            desc_label.set_markup(f'<span size="9000" color="#64748B">{description}</span>')
            desc_label.set_halign(Gtk.Align.START)
            name_box.append(desc_label)
            
            label_box.append(name_box)
            
            info_button = Gtk.Button()
            info_button.set_valign(Gtk.Align.CENTER)
            info_button.add_css_class("flat")
            info_button.add_css_class("info-button")

            info_label = Gtk.Label()
            info_label.set_markup('<span size="9000" color="#64748B">ⓘ</span>')
            info_button.set_child(info_label)

            tooltip_texts = {
                "ISO 27001": "Average security score from scans tagged with ISO 27001.\n\nNote: This percentage represents the average risk score,\nNOT actual ISO 27001 compliance certification.",
                "GDPR": "Average security score from scans tagged with GDPR.\n\nNote: This percentage represents the average risk score,\nNOT actual GDPR compliance certification.",
                "HIPAA": "Average security score from scans tagged with HIPAA.\n\nNote: This percentage represents the average risk score,\nNOT actual HIPAA compliance certification.",
                "PCI-DSS": "Average security score from scans tagged with PCI-DSS.\n\nNote: This percentage represents the average risk score,\nNOT actual PCI-DSS compliance certification."
            }
            description_text = tooltip_texts.get(name, f"{name} compliance checks and coverage score.")

            popover = Gtk.Popover()
            popover.set_has_arrow(True)
            popover.set_parent(info_button)
            popover.set_autohide(True)

            popover_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            popover_box.set_margin_top(8)
            popover_box.set_margin_bottom(8)
            popover_box.set_margin_start(10)
            popover_box.set_margin_end(10)

            popover_label = Gtk.Label()
            popover_label.set_wrap(True)
            popover_label.set_xalign(0.0)
            popover_label.set_markup(f'<span size="9000" color="#E5E7EB">{description_text}</span>')
            popover_box.append(popover_label)

            popover.set_child(popover_box)

            def on_info_clicked(_button, this_popover=popover):
                this_popover.popup()

            info_button.connect("clicked", on_info_clicked)
            label_box.append(info_button)

            header.append(label_box)

            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            header.append(spacer)

            score_box = Gtk.Box(spacing=6)
            
            score_label = Gtk.Label()
            color = "#D97706"

            score_label.set_markup(f'<span size="11500" weight="800" color="{color}">{score}%</span>')
            score_box.append(score_label)
            
            header.append(score_box)

            row.append(header)

            progress = Gtk.ProgressBar()
            progress.set_fraction(score / 100)
            progress.set_show_text(False)
            progress.set_hexpand(True)
            progress.add_css_class("standard-progress")

            row.append(progress)

            self.append(row)

    def update_standards(self, standards_list):

        max_iterations = 100
        iterations = 0
        while iterations < max_iterations:
            child = self.get_first_child()
            if child is None:
                break
            self.remove(child)
            iterations += 1

        self.standards = standards_list

        self._build_list()
