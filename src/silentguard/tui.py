from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static
from textual.binding import Binding
from pathlib import Path
from datetime import datetime
import json

from silentguard.monitor import (
    get_outgoing_connections,
    block_ip_in_rules,
    unblock_ip_in_rules,
    untrust_ip_in_rules,
    load_rules,
)
from silentguard.memory import add_entry, remove_entry, load_memory
from silentguard.actions import kill_process


class SilentGuardTUI(App):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("u", "toggle_unknown", "Toggle Unknown"),
        Binding("enter", "show_details", "Show Details"),
        Binding("b", "block", "Blocklist IP"),
        Binding("x", "unblock", "Unblock Selected"),
        Binding("k", "kill_process", "Kill Process"),
        Binding("m", "toggle_memory", "Toggle Memory View"),
        Binding("l", "toggle_rules", "Rules View"),
        Binding("t", "toggle_trust", "Toggle Trust"),
        Binding("e", "export_connections", "Export JSON"),
        Binding("h", "toggle_help", "Toggle Help"),
    ]

    HELP_TEXT = (
        "[bold]SilentGuard — Keyboard Shortcuts[/bold]\n\n"
        "  [bold]Q[/bold]  quit\n"
        "  [bold]R[/bold]  refresh\n"
        "  [bold]F[/bold]  toggle unknown-only filter\n"
        "  [bold]M[/bold]  memory view\n"
        "  [bold]L[/bold]  rules view\n"
        "  [bold]U[/bold]  unblock selected blocked IP from rules view\n"
        "  [bold]T[/bold]  untrust selected trusted IP from rules view\n"
        "  [bold]B[/bold]  block selected connection\n"
        "  [bold]K[/bold]  kill selected process\n"
        "  [bold]X[/bold]  unblock selected blocked connection\n"
        "  [bold]E[/bold]  export connections\n"
        "  [bold]/[/bold]  search/filter (Rules view)\n"
        "  [bold]H[/bold]  toggle this help\n\n"
        "[dim]Press H again to close.[/dim]"
    )

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("SilentGuard TUI", id="title")
        yield Static("Status: Ready | Press R to refresh", id="status")
        yield DataTable(id="connections_table")
        yield DataTable(id="memory_table")
        yield DataTable(id="rules_table")
        yield Static("Details: Press Enter on a row", id="details_full")
        yield Static(self.HELP_TEXT, id="help_panel")
        yield Footer()

    def on_mount(self) -> None:
        self.show_unknown_only = False
        self.memory_mode = False
        self.rules_mode = False
        self.selected_row_index = 0
        self.selected_memory_index = 0
        self.last_connections = []
        self._kill_pending_pid: int | None = None

        self.selected_rules_index = 0
        self._rules_row_types: list[tuple[str, str]] = []

        self.search_mode = False
        self.search_query = ""

        self.connections_table = self.query_one("#connections_table", DataTable)
        self.memory_table = self.query_one("#memory_table", DataTable)
        self.rules_table = self.query_one("#rules_table", DataTable)

        self.connections_table.cursor_type = "row"
        self.memory_table.cursor_type = "row"
        self.rules_table.cursor_type = "row"

        self.connections_table.add_columns(
            "Process", "PID", "Remote IP", "Port", "Status", "Trust"
        )
        self.memory_table.add_columns(
            "Action", "Target", "Reason", "Timestamp"
        )
        self.rules_table.add_columns("Category", "Value")

        self.refresh_connections()
        self.refresh_memory()
        self.refresh_rules()

        self.memory_table.display = False
        self.rules_table.display = False

        self.help_mode = False
        self.help_panel = self.query_one("#help_panel", Static)
        self.help_panel.display = False

    def refresh_connections(self) -> None:
        status = self.query_one("#status", Static)
        table = self.connections_table
        current_row = self.selected_row_index

        table.clear()

        try:
            connections = get_outgoing_connections()
            self.last_connections = connections

            if self.show_unknown_only:
                connections = [c for c in connections if c.trust == "Unknown"]

            for conn in connections[:500]:
                trust = str(conn.trust)

                if trust == "Unknown":
                    trust = f"[red]{trust}[/red]"
                elif trust == "Local":
                    trust = f"[yellow]{trust}[/yellow]"
                elif trust == "Blocked":
                    trust = f"[bold red]{trust}[/bold red]"
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
            known_count = sum(1 for c in connections if c.trust == "Known")
            trusted_count = sum(1 for c in connections if c.trust == "Trusted")
            local_count = sum(1 for c in connections if c.trust == "Local")
            blocked_count = sum(1 for c in connections if c.trust == "Blocked")

            status.update(
                f"Mode: Connections | Monitoring ({len(connections)} connections) | "
                f"Known: {known_count} | Unknown: {unknown_count} | "
                f"Trusted: {trusted_count} | Local: {local_count} | "
                f"Blocked: {blocked_count} | Press R to refresh"
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
        self._kill_pending_pid = None
        self.refresh_connections()
        self.refresh_memory()

    def action_toggle_unknown(self) -> None:
        if self.rules_mode:
            self._unblock_from_rules_view()
            return

        if self.memory_mode:
            return

        self.show_unknown_only = not self.show_unknown_only
        self.selected_row_index = 0
        self.refresh_connections()

    def _unblock_from_rules_view(self) -> None:
        status = self.query_one("#status", Static)
        idx = self.selected_rules_index
        if idx >= len(self._rules_row_types):
            return
        row_type, value = self._rules_row_types[idx]
        if row_type != "blocked_ip":
            status.update(
                "Mode: Rules | Select a Blocked IP row to unblock | Press L to return"
            )
            return
        removed = unblock_ip_in_rules(value)
        if removed:
            remove_entry(value)
            self.refresh_memory()
            rules = self.refresh_rules()
            blocked = len(rules.get("blocked_ips", []))
            trusted = len(rules.get("trusted_ips", []))
            known = len(rules.get("known_processes", []))
            status.update(
                f"Mode: Rules | Unblocked {value} | "
                f"Blocked IPs: {blocked} | Trusted IPs: {trusted} | Known Processes: {known} | "
                f"U to unblock selected blocked IP | Press L to return"
            )
        else:
            status.update(
                f"Mode: Rules | {value} was not in blocklist | Press L to return"
            )

    def action_toggle_trust(self) -> None:
        if not self.rules_mode:
            return

        status = self.query_one("#status", Static)
        idx = self.selected_rules_index
        if idx < 0 or idx >= len(self._rules_row_types):
            status.update("Mode: Rules | Select a Trusted IP row to untrust | Press L to return")
            return

        row_type, value = self._rules_row_types[idx]

        if row_type == "trusted_ip":
            removed = untrust_ip_in_rules(value)
            rules = self.refresh_rules()
            blocked = len(rules.get("blocked_ips", []))
            trusted = len(rules.get("trusted_ips", []))
            known = len(rules.get("known_processes", []))
            if removed:
                status.update(
                    f"Mode: Rules | Untrusted {value} | "
                    f"Blocked IPs: {blocked} | Trusted IPs: {trusted} | Known Processes: {known} | "
                    f"Press L to return"
                )
            else:
                status.update(
                    f"Mode: Rules | {value} was not in trusted IPs | Press L to return"
                )
        elif row_type == "blocked_ip":
            status.update(
                f"Mode: Rules | Blocked IPs must be unblocked before they can be trusted | "
                f"Press L to return"
            )
        else:
            status.update(
                "Mode: Rules | Select a Trusted IP row to toggle trust | Press L to return"
            )

    def action_toggle_memory(self) -> None:
        if self.rules_mode:
            return
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

    def _filter_rules(self, query: str, blocked: list, trusted: list, known: list):
        if not query:
            return blocked, trusted, known
        q = query.lower()
        return (
            [ip for ip in blocked if q in str(ip).lower()],
            [ip for ip in trusted if q in str(ip).lower()],
            [proc for proc in known if q in str(proc).lower()],
        )

    def refresh_rules(self) -> dict:
        table = self.rules_table
        table.clear()
        self._rules_row_types = []

        rules = load_rules()
        blocked_all = rules.get("blocked_ips", [])
        trusted_all = rules.get("trusted_ips", [])
        known_all = rules.get("known_processes", [])

        query = self.search_query if getattr(self, "search_mode", False) else ""
        blocked, trusted, known = self._filter_rules(
            query, blocked_all, trusted_all, known_all
        )

        if query and not (blocked or trusted or known):
            table.add_row("[dim](no matches)[/dim]", "")
            self._rules_row_types.append(("empty", ""))
            return rules

        table.add_row(f"[bold red]Blocked IPs ({len(blocked)})[/bold red]", "")
        self._rules_row_types.append(("header", ""))
        for ip in blocked:
            table.add_row("  [bold red]Blocked IP[/bold red]", str(ip))
            self._rules_row_types.append(("blocked_ip", str(ip)))
        if not blocked:
            table.add_row("  [dim](none)[/dim]", "")
            self._rules_row_types.append(("empty", ""))

        table.add_row("", "")
        self._rules_row_types.append(("spacer", ""))

        table.add_row(f"[green]Trusted IPs ({len(trusted)})[/green]", "")
        self._rules_row_types.append(("header", ""))
        for ip in trusted:
            table.add_row("  [green]Trusted IP[/green]", str(ip))
            self._rules_row_types.append(("trusted_ip", str(ip)))
        if not trusted:
            table.add_row("  [dim](none)[/dim]", "")
            self._rules_row_types.append(("empty", ""))

        table.add_row("", "")
        self._rules_row_types.append(("spacer", ""))

        table.add_row(f"[yellow]Known Processes ({len(known)})[/yellow]", "")
        self._rules_row_types.append(("header", ""))
        for proc in known:
            table.add_row("  [yellow]Known Process[/yellow]", str(proc))
            self._rules_row_types.append(("known_process", str(proc)))
        if not known:
            table.add_row("  [dim](none)[/dim]", "")
            self._rules_row_types.append(("empty", ""))

        return rules

    def action_toggle_rules(self) -> None:
        status = self.query_one("#status", Static)
        details = self.query_one("#details_full", Static)

        self.rules_mode = not self.rules_mode

        if self.rules_mode:
            self.connections_table.display = False
            self.memory_table.display = False
            self.rules_table.display = True
            self.memory_mode = False
            self.selected_rules_index = 0
            rules = self.refresh_rules()
            blocked = len(rules.get("blocked_ips", []))
            trusted = len(rules.get("trusted_ips", []))
            known = len(rules.get("known_processes", []))
            status.update(
                f"Mode: Rules | "
                f"Blocked IPs: {blocked} | Trusted IPs: {trusted} | Known Processes: {known} | "
                f"U to unblock selected blocked IP | Press L to return"
            )
            details.update("Rules: select a Blocked IP row and press U to unblock")
        else:
            self.rules_table.display = False
            self.connections_table.display = True
            self.refresh_connections()
            details.update("Details: Press Enter on a row")

    def action_toggle_help(self) -> None:
        status = self.query_one("#status", Static)
        details = self.query_one("#details_full", Static)

        if not self.help_mode:
            self._pre_help_view = {
                "connections": self.connections_table.display,
                "memory": self.memory_table.display,
                "rules": self.rules_table.display,
                "details": details.display,
            }
            self.connections_table.display = False
            self.memory_table.display = False
            self.rules_table.display = False
            details.display = False
            self.help_panel.display = True
            self.help_mode = True
            status.update("Mode: Help | Press H to close")
        else:
            prev = getattr(self, "_pre_help_view", {})
            self.help_panel.display = False
            self.connections_table.display = prev.get("connections", not (self.memory_mode or self.rules_mode))
            self.memory_table.display = prev.get("memory", self.memory_mode)
            self.rules_table.display = prev.get("rules", self.rules_mode)
            details.display = prev.get("details", True)
            self.help_mode = False
            if self.rules_mode:
                rules = load_rules()
                blocked = len(rules.get("blocked_ips", []))
                trusted = len(rules.get("trusted_ips", []))
                known = len(rules.get("known_processes", []))
                status.update(
                    f"Mode: Rules | "
                    f"Blocked IPs: {blocked} | Trusted IPs: {trusted} | Known Processes: {known} | "
                    f"U to unblock selected blocked IP | Press L to return"
                )
            elif self.memory_mode:
                status.update("Mode: Memory | Use ↑ ↓ to select, X to remove entry")
            else:
                status.update("Mode: Connections | Press R to refresh")

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
        if self.memory_mode or self.rules_mode:
            return

        status = self.query_one("#status", Static)

        try:
            row = self.connections_table.get_row_at(self.selected_row_index)
            ip = str(row[2])

            try:
                added = block_ip_in_rules(ip)
            except ValueError as guard_error:
                status.update(
                    f"Mode: Connections | Refused to block {ip}: {guard_error}"
                )
                return

            if added:
                add_entry("block_ip", ip, "from TUI")
                status.update(f"Mode: Connections | Added {ip} to blocklist")
            else:
                status.update(f"Mode: Connections | {ip} already in blocklist")
            self.refresh_memory()
            self.refresh_connections()
        except Exception as exc:
            status.update(f"Status: Error while blocklisting IP - {exc}")

    def action_kill_process(self) -> None:
        if self.memory_mode or self.rules_mode:
            return

        status = self.query_one("#status", Static)

        try:
            row = self.connections_table.get_row_at(self.selected_row_index)
            pid = int(row[1])
            process_name = str(row[0])
        except Exception as exc:
            status.update(f"Status: Could not read selected row — {exc}")
            return

        if pid <= 0:
            self._kill_pending_pid = None
            status.update("Kill: No PID available for this connection")
            return

        if self._kill_pending_pid != pid:
            self._kill_pending_pid = pid
            status.update(
                f"Kill: Press K again to send SIGTERM to PID {pid} ({process_name}) — "
                f"move cursor or press R to cancel"
            )
            return

        self._kill_pending_pid = None
        success, message = kill_process(pid)
        add_entry("kill_process", str(pid), message)
        self.refresh_memory()
        self.refresh_connections()
        status.update(f"Kill: {message}")

    def action_unblock(self) -> None:
        if self.rules_mode:
            return
        status = self.query_one("#status", Static)

        try:
            if self.memory_mode:
                row = self.memory_table.get_row_at(self.selected_memory_index)
                action = str(row[0])
                target = str(row[1])

                remove_entry(target)
                if action == "block_ip":
                    unblock_ip_in_rules(target)
                self.refresh_memory()
                status.update(f"Mode: Memory | Removed {target} from memory")
            else:
                row = self.connections_table.get_row_at(self.selected_row_index)
                ip = str(row[2])

                remove_entry(ip)
                unblock_ip_in_rules(ip)
                self.refresh_memory()
                self.refresh_connections()
                status.update(f"Mode: Connections | Removed {ip} from blocklist")
        except Exception as exc:
            status.update(f"Status: Error while unblocking - {exc}")

    def action_export_connections(self) -> None:
        if self.rules_mode:
            return
        status = self.query_one("#status", Static)

        try:
            export_dir = Path.home() / ".silentguard_exports"
            export_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            export_file = export_dir / f"connections_{timestamp}.json"
            payload = [
                {
                    "process_name": c.process_name,
                    "pid": c.pid,
                    "remote_ip": c.remote_ip,
                    "remote_port": c.remote_port,
                    "status": c.status,
                    "trust": c.trust,
                }
                for c in self.last_connections
            ]
            with open(export_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            status.update(f"Mode: Connections | Exported {len(payload)} rows to {export_file}")
        except Exception as exc:
            status.update(f"Status: Error while exporting - {exc}")

    def _update_search_status(self) -> None:
        status = self.query_one("#status", Static)
        status.update(
            f"Mode: Rules | Search: /{self.search_query}_ | "
            f"Type to filter | Esc or Enter to exit"
        )

    def _enter_search_mode(self) -> None:
        if not self.rules_mode:
            return
        self.search_mode = True
        self.search_query = ""
        self.refresh_rules()
        self._update_search_status()

    def _exit_search_mode(self) -> None:
        self.search_mode = False
        self.search_query = ""
        rules = self.refresh_rules()
        status = self.query_one("#status", Static)
        blocked = len(rules.get("blocked_ips", []))
        trusted = len(rules.get("trusted_ips", []))
        known = len(rules.get("known_processes", []))
        status.update(
            f"Mode: Rules | "
            f"Blocked IPs: {blocked} | Trusted IPs: {trusted} | Known Processes: {known} | "
            f"U to unblock selected blocked IP | Press L to return"
        )

    def on_key(self, event) -> None:
        if self.search_mode:
            key = event.key
            if key in ("escape", "enter"):
                self._exit_search_mode()
                event.stop()
                event.prevent_default()
                return
            if key == "backspace":
                self.search_query = self.search_query[:-1]
                self.refresh_rules()
                self._update_search_status()
                event.stop()
                event.prevent_default()
                return
            char = getattr(event, "character", None)
            if char and len(char) == 1 and char.isprintable():
                self.search_query += char
                self.refresh_rules()
                self._update_search_status()
                event.stop()
                event.prevent_default()
            return

        if self.rules_mode and getattr(event, "character", None) == "/":
            self._enter_search_mode()
            event.stop()
            event.prevent_default()

    def on_data_table_row_selected(self, event) -> None:
        if event.data_table.id == "rules_table":
            self.selected_rules_index = event.cursor_row
            return
        if event.data_table.id == "memory_table":
            self.selected_memory_index = event.cursor_row
        else:
            self.selected_row_index = event.cursor_row

        self.action_show_details()

    def _update_rules_status_for_selection(self) -> None:
        if not self.rules_mode:
            return
        status = self.query_one("#status", Static)
        idx = self.selected_rules_index
        if idx < 0 or idx >= len(self._rules_row_types):
            return
        row_type, value = self._rules_row_types[idx]
        if row_type == "blocked_ip":
            status.update(f"Selected blocked IP: {value} — press U to unblock")
        elif row_type == "trusted_ip":
            status.update(f"Selected trusted IP: {value}")
        elif row_type == "known_process":
            status.update(f"Selected known process: {value}")
        else:
            status.update("Mode: Rules | Press L to return")

    def _find_actionable_rules_row(self, start: int, direction: int) -> int | None:
        actionable = {"blocked_ip", "trusted_ip", "known_process"}
        n = len(self._rules_row_types)
        idx = start
        while 0 <= idx < n:
            if self._rules_row_types[idx][0] in actionable:
                return idx
            idx += direction
        return None

    def on_data_table_cursor_moved(self, event) -> None:
        if event.data_table.id == "rules_table":
            new_idx = event.cursor_row
            actionable = {"blocked_ip", "trusted_ip", "known_process"}
            if 0 <= new_idx < len(self._rules_row_types) and \
                    self._rules_row_types[new_idx][0] not in actionable:
                direction = 1 if new_idx >= self.selected_rules_index else -1
                target = self._find_actionable_rules_row(new_idx, direction)
                if target is not None and target != new_idx:
                    self.selected_rules_index = target
                    self.rules_table.move_cursor(row=target, column=0)
                    self._update_rules_status_for_selection()
                    return
            self.selected_rules_index = new_idx
            self._update_rules_status_for_selection()
            return
        if event.data_table.id == "memory_table":
            self.selected_memory_index = event.cursor_row
        else:
            self.selected_row_index = event.cursor_row
            self._kill_pending_pid = None


def main() -> None:
    app = SilentGuardTUI()
    app.run()


if __name__ == "__main__":
    main()
