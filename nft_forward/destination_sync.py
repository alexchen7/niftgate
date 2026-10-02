from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from .config import Settings
from .destination import resolve_ipv4
from .nft import apply_lock, write_and_apply
from .state import State


def sync_destinations(settings: Settings, apply_rules: bool = True) -> int:
    if not settings.paths:
        raise ValueError("missing configured paths")
    state = State(settings.paths.state_db, settings.paths.audit_log)
    try:
        snapshot = [rule for rule in state.rules() if rule.dest_host]
    finally:
        state.close()
    if not snapshot:
        return 0

    def lookup(host):
        try:
            return host, resolve_ipv4(host, settings.ddns_timeout), ""
        except Exception as exc:
            return host, [], str(exc)

    hosts = sorted({rule.dest_host for rule in snapshot})
    with ThreadPoolExecutor(max_workers=min(8, len(hosts))) as executor:
        results = {host: (ips, error) for host, ips, error in executor.map(lookup, hosts)}
    previous = {rule.id: rule for rule in snapshot}
    with apply_lock(settings):
        state = State(settings.paths.state_db, settings.paths.audit_log)
        try:
            for host, (_, error) in results.items():
                key = f"destination_dns_error:{host}"
                if state.get_meta(key) != error:
                    state.set_meta(key, error)
                    state.audit("destination_dns_failed" if error else "destination_dns_recovered", host=host, error=error)
            updates = []
            with state.conn:
                state.conn.execute("BEGIN IMMEDIATE")
                for rule in state.rules():
                    old = previous.get(rule.id)
                    # DNS was queried without holding the firewall lock. Discard
                    # stale answers if the user edited the destination meanwhile.
                    if not old or (rule.dest_host, rule.dest_ip) != (old.dest_host, old.dest_ip):
                        continue
                    ips, error = results[rule.dest_host]
                    if error or rule.dest_ip in ips:
                        continue
                    updated = replace(rule, dest_ip=ips[0])
                    state.update_rule(updated)
                    updates.append((rule, updated))
                if updates and apply_rules:
                    write_and_apply(settings, state, apply=True, lock_held=True)
            for old, updated in updates:
                state.audit("destination_changed", lport=updated.lport, host=updated.dest_host,
                            old_ip=old.dest_ip, new_ip=updated.dest_ip)
            return len(updates)
        except Exception as exc:
            state.audit("destination_apply_failed", error=str(exc))
            raise
        finally:
            state.close()
