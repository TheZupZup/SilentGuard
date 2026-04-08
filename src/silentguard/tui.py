from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static
from textual.binding import Binding

from silentguard.monitor import get_outgoing_connections
from silentguard.memory import add_entry, remove_entry, load_memory


class SilentGuardTUI(App):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("u", "toggle_unknown", "Toggle Unknown"),
        Binding("enter", "show_details", "Show Details"),
        Binding("b", "block", "Block IP"),
        Binding("x", "unblock", "Unblock Selected"),
        Binding("m", "toggle_memory", "Toggle Memory View"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("SilentGuard TUI", id="title")
        yield Static("Status: Ready | Press R to refresh", id="status")
        yield DataTable(id="connections_table")
        yield DataTable(id="memory_table")
        yield Static("Details: Press Enter on a row", id="details_full")
        yield Footer()

    def on_mount(self) -> None:
        self.show_unknown_only = False
        self.memory_mode = False
        self.selected_row_index = 0
        self.selected_memory_index = 0

        self.connections_table = self.query_one("#connections_table", DataTable)
        self.memory_table = self.query_one("#memory_table", DataTable)

        self.connections_table.cursor_type = "row"
        self.memory_table.cursor_type = "row"

        self.connections_table.add_columns(
            "Process", "PID", "Remote IP", "Port", "Status", "Trust"
        )
        self.memory_table.add_columns(
            "Action", "Target", "Reason", "Timestamp"
        )

        self.refresh_connections()
        self.refresh_memory()

        self.memory_table.display = False

    def refresh_connections(self) -> None:
        status = self.query_one("#status", Static)
        table = self.connections_table
        current_row = self.selected_row_index

        table.clear()

        try:
            connections = get_outgoing_connections()

            if self.show_unknown_only:
                connections = [c for c in connections if c.trust == "Unknown"]

            for conn in connections[:500]:
                trust = str(conn.trust)

                if trust == "Unknown":
                    trust = f"[red]{trust}[/red]"
                elif trust == "Local":
                    trust = f"[yellow]{trust}[/yellow]"
                else:
                    trust = f"[green]{trust}[/green]"

                table.add_row(
                    str(conn.process_name),
                    str(conn.pid or 0),
                    str(conn.remote_ip),
                    str(conn.remote_port),
                    str(conn.status),
                    trust,
                )

            if len(connections) > 0:
                if current_row >= len(connections):
                    current_row = len(connections) - 1
                self.selected_row_index = current_row
                table.move_cursor(row=current_row, column=0)
            else:
                self.selected_row_index = 0

            unknown_count = sum(1 for c in connections if c.trust == "Unknown")

            status.update(
                f"Mode: Connections | Monitoring ({len(connections)} connections) | "
                f"Unknown: {unknown_count} | Press R to refresh"
                + (" | Unknown only: ON" if self.show_unknown_only else "")
            )

        except Exception as exc:
            status.update(f"Status: Error - {exc}")

    def refresh_memory(self) -> None:
        table = self.memory_table
        data = load_memory()
        current_row = self.selected_memory_index

        table.clear()

        for entry in data:
            table.add_row(
                str(entry.get("action", "")),
                str(entry.get("target", "")),
                str(entry.get("reason", "")),
                str(entry.get("timestamp", "")),
            )

        if len(data) > 0:
            if current_row >= len(data):
                current_row = len(data) - 1
            self.selected_memory_index = current_row
            table.move_cursor(row=current_row, column=0)
        else:
            self.selected_memory_index = 0

    def action_refresh(self) -> None:
        self.refresh_connections()
        self.refresh_memory()

    def action_toggle_unknown(self) -> None:
        if self.memory_mode:
            return

        self.show_unknown_only = not self.show_unknown_only
        self.selected_row_index = 0
        self.refresh_connections()

    def action_toggle_memory(self) -> None:
        status = self.query_one("#status", Static)
        details = self.query_one("#details_full", Static)

        self.memory_mode = not self.memory_mode

        if self.memory_mode:
            self.connections_table.display = False
            self.memory_table.display = True
            self.refresh_memory()
            status.update("Mode: Memory | Use ↑ ↓ to select, X to remove entry")
            details.update("Details: Press Enter on a memory row")
        else:
            self.memory_table.display = False
            self.connections_table.display = True
            self.refresh_connections()
            details.update("Details: Press Enter on a row")

    def action_show_details(self) -> None:
        details = self.query_one("#details_full", Static)

        try:
            if self.memory_mode:
                row = self.memory_table.get_row_at(self.selected_memory_index)
                details.update(
                    f"Memory Details: {row[0]} | {row[1]} | {row[2]} | {row[3]}"
                )
            else:
                row = self.connections_table.get_row_at(self.selected_row_index)
                details.update(
                    f"Details: {row[0]} (PID {row[1]}) -> "
                    f"{row[2]}:{row[3]} | {row[4]} | {row[5]}"
                )
        except Exception:
            details.update("Details: None")

    def action_block(self) -> None:
        if self.memory_mode:
            return

        status = self.query_one("#status", Static)

        try:
            row = self.connections_table.get_row_at(self.selected_row_index)
            ip = str(row[2])

            add_entry("block_ip", ip, "from TUI")
            status.update(f"Mode: Connections | Saved {ip} to memory")
            self.refresh_memory()
        except Exception as exc:
            status.update(f"Status: Error while saving IP - {exc}")

    def action_unblock(self) -> None:
        status = self.query_one("#status", Static)

        try:
            if self.memory_mode:
                row = self.memory_table.get_row_at(self.selected_memory_index)
                target = str(row[1])

                remove_entry(target)
                self.refresh_memory()
                status.update(f"Mode: Memory | Removed {target} from memory")
            else:
                row = self.connections_table.get_row_at(self.selected_row_index)
                ip = str(row[2])

                remove_entry(ip)
                self.refresh_memory()
                status.update(f"Mode: Connections | Removed {ip} from memory")
        except Exception as exc:
            status.update(f"Status: Error while unblocking - {exc}")

    def on_data_table_row_selected(self, event) -> None:
        if event.data_table.id == "memory_table":
            self.selected_memory_index = event.cursor_row
        else:
            self.selected_row_index = event.cursor_row

        self.action_show_details()

    def on_data_table_cursor_moved(self, event) -> None:
        if event.data_table.id == "memory_table":
            self.selected_memory_index = event.cursor_row
        else:
            self.selected_row_index = event.cursor_row


def main() -> None:
    app = SilentGuardTUI()
    app.run()


if __name__ == "__main__":
    main()
