"""
blocked_view.py

The rules view (blocked IPs, trusted IPs, known processes) is implemented
directly in tui.py as a third DataTable toggled by the L key binding.

Data source: load_rules() from monitor.py → ~/.silentguard_rules.json
"""
