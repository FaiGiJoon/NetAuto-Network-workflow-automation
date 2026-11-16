"""Automatic fixes shared by several workflows."""

from __future__ import annotations

from . import notify, ticket
from .http import HttpError
from .mikrotik import RouterOS
from .safety import RateLimiter, dry_run


def poe_restart(device: str, switch: str, port: str, duration: str = "5s", max_per_day: int = 3,
                router: RouterOS | None = None) -> str:
    """Power-cycle the PoE port of a device that went down.

    At most `max_per_day` times per device. After that it stops and opens a
    ticket, because a device that keeps dying needs a person, not a reboot.
    Returns: restarted | dry-run | limit | no-port | error
    """
    if not port or not switch or port.startswith("{$"):
        print(f"{device}: no PoE switch/port known for this device")
        return "no-port"
    if not RateLimiter("poe-restarts", max_per_day, 86400).allow(device):
        ticket.open_ticket(f"poe:{device}", f"{device} keeps going down",
                           f"{device} on {switch} {port} was already restarted {max_per_day} times "
                           "in the last 24 hours. Automatic restarts are paused for this device. "
                           "Check the cable, the device and the switch port.")
        notify.send(f"netops: {device} is down again, restart limit reached. Ticket opened.")
        return "limit"
    if dry_run():
        print(f"[dry-run] would power-cycle {switch} {port} for {device}")
        return "dry-run"
    router = router or RouterOS.from_env(host=switch)
    try:
        router.poe_power_cycle(port, duration)
    except (HttpError, OSError) as exc:
        notify.send(f"netops: PoE restart of {device} ({switch} {port}) FAILED: {exc}")
        return "error"
    notify.send(f"netops: {device} was down, power-cycled {switch} {port}")
    return "restarted"
