import ipaddress
import shutil
import subprocess


class ActionError(RuntimeError):
    pass


def kill_process(pid: int) -> None:
    """Future feature: kill a process by PID."""
    pass


def _validate_ip(ip: str) -> ipaddress._BaseAddress:
    try:
        return ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ActionError(f"Invalid IP address: {ip}") from exc


def _run_command(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "unknown error"
        raise ActionError(f"Command failed ({' '.join(command)}): {stderr}") from exc


def _detect_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("iptables"):
        return "iptables"
    raise ActionError("No supported firewall backend found (ufw/iptables)")


def block_ip(ip: str) -> str:
    """Block an IP address using available firewall backend."""
    addr = _validate_ip(ip)
    backend = _detect_backend()

    if backend == "ufw":
        _run_command(["ufw", "deny", "out", "to", str(addr)])
        return backend

    if addr.version == 6:
        iptables_cmd = shutil.which("ip6tables")
        if not iptables_cmd:
            raise ActionError("ip6tables not available for IPv6 block")
    else:
        iptables_cmd = shutil.which("iptables")
        if not iptables_cmd:
            raise ActionError("iptables not available for IPv4 block")

    _run_command([iptables_cmd, "-A", "OUTPUT", "-d", str(addr), "-j", "REJECT"])
    return backend


def unblock_ip(ip: str) -> str:
    """Unblock an IP address using available firewall backend."""
    addr = _validate_ip(ip)
    backend = _detect_backend()

    if backend == "ufw":
        _run_command(["ufw", "--force", "delete", "deny", "out", "to", str(addr)])
        return backend

    if addr.version == 6:
        iptables_cmd = shutil.which("ip6tables")
        if not iptables_cmd:
            raise ActionError("ip6tables not available for IPv6 unblock")
    else:
        iptables_cmd = shutil.which("iptables")
        if not iptables_cmd:
            raise ActionError("iptables not available for IPv4 unblock")

    _run_command([iptables_cmd, "-D", "OUTPUT", "-d", str(addr), "-j", "REJECT"])
    return backend
