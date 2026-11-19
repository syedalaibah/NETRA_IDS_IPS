from __future__ import annotations

import ctypes
import ipaddress
import json
import platform
import subprocess
from dataclasses import dataclass
from threading import Lock

from config import ADMIN_PASSWORD_CONFIGURED, ALLOW_REAL_FIREWALL
from utils.security import is_valid_ip


@dataclass
class FirewallResult:
    ok: bool
    message: str
    rules: tuple[dict, ...] = ()


_lock = Lock()
_rules_query = """
function Get-NetraRules($store) {
    Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop |
        Where-Object {
            $_.Group -eq 'NETRA IDS/IPS' -or $_.DisplayName -like 'IDS_Block_*'
        }
}
"""


def firewall_status() -> str | None:
    if platform.system() != "Windows":
        return "Windows Defender Firewall is required."
    if not ALLOW_REAL_FIREWALL:
        return "Set IDS_ALLOW_REAL_FIREWALL=1 and restart Netra to apply rules."
    if not ADMIN_PASSWORD_CONFIGURED:
        return "Set a custom admin password before applying firewall rules."
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return "Start Netra from an Administrator PowerShell to manage rules."
    return None


def _powershell(script: str) -> str:
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference = 'Stop'; " + _rules_query + script],
        capture_output=True, text=True, errors="replace", timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}")
    return proc.stdout.strip()


def _change(ip: str, apply: bool, block: bool) -> FirewallResult:
    if not is_valid_ip(ip):
        return FirewallResult(False, "Enter a valid IPv4 or IPv6 address.")
    address = ipaddress.ip_address(ip.strip())
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if block and (address.is_loopback or address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255"):
        return FirewallResult(False, "Enter a unicast remote IP address.")
    target = str(address)
    verb = "Block" if block else "Unblock"
    if not apply:
        return FirewallResult(True, f"Preview only. {verb} {target} on inbound and outbound traffic.")
    if reason := firewall_status():
        return FirewallResult(False, reason)

    # Only canonical or validated IP addresses are interpolated into the script.
    script = f"""
    $ip = '{target}'
    $names = @('Netra-Block-Inbound-' + $ip; 'Netra-Block-Outbound-' + $ip)
    function Match-NetraIp($rule) {{
        if ($rule.Name -in $names) {{ return $true }}
        if ($rule.DisplayName -notmatch '^IDS_Block_([0-9a-f.:]+)$') {{ return $false }}
        $legacy = $null
        if (-not [ipaddress]::TryParse($Matches[1], [ref]$legacy)) {{ return $false }}
        if ($legacy.IsIPv4MappedToIPv6) {{ $legacy = $legacy.MapToIPv4() }}
        return $legacy.Equals([ipaddress]$ip)
    }}
    $existing = @(Get-NetraRules 'PersistentStore' | Where-Object {{ Match-NetraIp $_ }})
    """
    if block:
        script += """
        $created = @()
        try {
            foreach ($direction in @('Inbound', 'Outbound')) {
                $name = "Netra-Block-$direction-$ip"
                if ($name -notin $existing.Name) {
                    $rule = @{
                        PolicyStore = 'PersistentStore'
                        Name = $name
                        DisplayName = "Netra $direction block $ip"
                        Group = 'NETRA IDS/IPS'
                        Direction = $direction
                        Action = 'Block'
                        RemoteAddress = $ip
                        Enabled = 'True'
                        Profile = 'Any'
                    }
                    New-NetFirewallRule @rule | Out-Null
                    $created += $name
                }
            }
            $active = @(Get-NetraRules 'ActiveStore' | Where-Object {
                $_.Name -in $names -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and
                $_.Name -eq "Netra-Block-$($_.Direction)-$ip" -and
                $_.Profile -eq 'Any' -and
                [bool](($_ | Get-NetFirewallAddressFilter).RemoteAddress | Where-Object {
                    $remote = $_ -replace '/(32|128)$', ''
                    $parsed = $null
                    [ipaddress]::TryParse($remote, [ref]$parsed) -and $parsed.Equals([ipaddress]$ip)
                })
            })
            if (@($active.Name | Sort-Object -Unique).Count -ne 2) {
                throw 'Windows did not report both enabled block rules in active policy.'
            }
        } catch {
            foreach ($name in $created) {
                Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue
            }
            throw
        }
        """
    else:
        script += """
        $existing | ForEach-Object {
            Remove-NetFirewallRule -PolicyStore PersistentStore -Name $_.Name
        }
        if (@(Get-NetraRules 'ActiveStore' | Where-Object { Match-NetraIp $_ }).Count) {
            throw 'A matching rule remains in active Windows policy.'
        }
        """
    try:
        with _lock:
            _powershell(script)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return FirewallResult(False, f"{verb} could not be verified. {exc}")
    message = (f"Windows active policy contains both block rules for {target}." if block
               else f"Windows active policy has no matching Netra block rules for {target}.")
    return FirewallResult(True, message)


def block_ip(ip: str, *, apply: bool) -> FirewallResult:
    return _change(ip, apply, block=True)


def unblock_ip(ip: str, *, apply: bool) -> FirewallResult:
    return _change(ip, apply, block=False)


def list_ids_rules() -> FirewallResult:
    if platform.system() != "Windows" or not ctypes.windll.shell32.IsUserAnAdmin():
        return FirewallResult(False, "Administrator PowerShell is required to read Windows Firewall policy.")
    try:
        with _lock:
            output = _powershell("""
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {
                $_.Enabled -ne 'True'
            } | Select-Object -ExpandProperty Name)
            $rules = @(Get-NetraRules 'ActiveStore' | ForEach-Object {
                [pscustomobject]@{
                    Rule = $_.DisplayName
                    Direction = [string]$_.Direction
                    Enabled = [string]$_.Enabled
                    Action = [string]$_.Action
                    IP = (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ', ')
                }
            })
            @{rules = $rules; disabled_profiles = $profiles} | ConvertTo-Json -Compress -Depth 4
            """)
        inventory = json.loads(output)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        return FirewallResult(False, f"Could not read Windows Firewall policy. {exc}")
    disabled = ", ".join(inventory["disabled_profiles"])
    message = f"Firewall disabled for these profiles: {disabled}." if disabled else "Windows Firewall profiles are enabled."
    return FirewallResult(True, message, tuple(inventory["rules"]))
