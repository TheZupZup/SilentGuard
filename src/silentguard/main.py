import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from silentguard.monitor import get_outgoing_connections


class SilentGuardWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="SilentGuard")
        self.set_default_size(1000, 600)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        root.set_border_width(12)
        self.add(root)

        title = Gtk.Label()
        title.set_markup("<span size='x-large' weight='bold'>SilentGuard</span>")
        title.set_xalign(0)
        root.pack_start(title, False, False, 0)

        subtitle = Gtk.Label(label="A lightweight network & privacy monitor with smart alerts")
        subtitle.set_xalign(0)
        root.pack_start(subtitle, False, False, 0)

        button_row = Gtk.Box(spacing=8)
        root.pack_start(button_row, False, False, 0)

        self.start_button = Gtk.Button(label="Start Monitoring")
        self.start_button.connect("clicked", self.on_start_clicked)
        button_row.pack_start(self.start_button, False, False, 0)

        self.stop_button = Gtk.Button(label="Stop")
        self.stop_button.connect("clicked", self.on_stop_clicked)
        self.stop_button.set_sensitive(False)
        button_row.pack_start(self.stop_button, False, False, 0)

        self.status_label = Gtk.Label(label="Status: Ready")
        self.status_label.set_xalign(0)
        root.pack_start(self.status_label, False, False, 0)

        self.store = Gtk.ListStore(str, int, str, int, str, str)
        self.tree = Gtk.TreeView(model=self.store)

        columns = [
            ("Process", 0),
            ("PID", 1),
            ("Remote IP", 2),
            ("Port", 3),
            ("Status", 4),
            ("Trust", 5),
        ]

        for title_text, index in columns:
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(title_text, renderer, text=index)
            self.tree.append_column(column)

        tree_scroll = Gtk.ScrolledWindow()
        tree_scroll.set_hexpand(True)
        tree_scroll.set_vexpand(True)
        tree_scroll.add(self.tree)
        root.pack_start(tree_scroll, True, True, 0)

        log_label = Gtk.Label()
        log_label.set_markup("<b>Activity Log</b>")
        log_label.set_xalign(0)
        root.pack_start(log_label, False, False, 0)

        self.log_buffer = Gtk.TextBuffer()
        self.log_view = Gtk.TextView(buffer=self.log_buffer)
        self.log_view.set_editable(False)
        self.log_view.set_cursor_visible(False)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)

        log_scroll = Gtk.ScrolledWindow()
        log_scroll.set_hexpand(True)
        log_scroll.set_vexpand(True)
        log_scroll.set_size_request(-1, 140)
        log_scroll.add(self.log_view)
        root.pack_start(log_scroll, False, True, 0)

        self.timer_id = None
        self.append_log("SilentGuard started")
        self.append_log("Waiting for monitoring to begin...")

    def append_log(self, message: str) -> None:
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, f"{message}\n")

    def on_start_clicked(self, _button) -> None:
        if self.timer_id is None:
            self.timer_id = GLib.timeout_add_seconds(2, self.refresh_connections)
            self.status_label.set_text("Status: Monitoring")
            self.start_button.set_sensitive(False)
            self.stop_button.set_sensitive(True)
            self.append_log("Monitoring started")
            self.refresh_connections()

    def on_stop_clicked(self, _button) -> None:
        if self.timer_id is not None:
            GLib.source_remove(self.timer_id)
            self.timer_id = None

        self.status_label.set_text("Status: Stopped")
        self.start_button.set_sensitive(True)
        self.stop_button.set_sensitive(False)
        self.append_log("Monitoring stopped")

    def refresh_connections(self) -> bool:
        self.store.clear()

        try:
            connections = get_outgoing_connections()

            for conn in connections:
                self.store.append(
                    [
                        conn.process_name,
                        conn.pid or 0,
                        conn.remote_ip,
                        conn.remote_port,
                        conn.status,
                        conn.trust,
                    ]
                )

            self.status_label.set_text(f"Status: Monitoring ({len(connections)} connections)")
        except Exception as exc:
            self.status_label.set_text("Status: Error")
            self.append_log(f"Error while reading connections: {exc}")

        return True


def main() -> None:
    win = SilentGuardWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()


if __name__ == "__main__":
    main()
