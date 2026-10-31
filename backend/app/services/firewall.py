"""
SILENT WITNESS - Firewall Integration Service
=============================================
Dedicated module for Linux iptables integration with strict safeguards.

SAFEGUARD RULES IMPLEMENTED:
----------------------------
1. Dry-run mode by default. Real firewall modification is strictly disabled unless
   both REAL_FIREWALL_ENABLED is True and the system is Linux.
2. Windows & unsupported platforms automatically use simulated blocking.
3. IP validation is mandatory before any command creation.
4. Loopback, private gateways, DNS, multicast, link-local, and broadcast are rejected.
5. All firewall commands use argument lists (subprocess.run), NEVER shell=True.
6. Frontend input never passes arbitrary shell arguments.
7. Only rules created by this application (tagged with comment 'silent_witness_block')
   are ever managed or deleted. Never flushes or resets system firewall.
8. Logs success/failure and verifies rule existence.
"""

import sys
import subprocess
import logging
from typing import Tuple, Optional
from app.config import REAL_FIREWALL_ENABLED, DRY_RUN_MODE
from app.utils.validation import is_safe_to_block, validate_ip

logger = logging.getLogger("silent_witness.firewall")

RULE_TAG = "silent_witness_block"


class FirewallManager:
    """Manages system firewall interactions safely."""

    def __init__(self):
        self.is_linux = sys.platform.startswith("linux")
        self.real_enabled = REAL_FIREWALL_ENABLED and self.is_linux

    def check_support(self) -> dict:
        """Check if real firewall modification is supported on this platform."""
        return {
            "platform": sys.platform,
            "is_linux": self.is_linux,
            "real_firewall_supported": self.is_linux,
            "real_firewall_enabled": self.real_enabled,
            "dry_run_default": DRY_RUN_MODE
        }

    def block_ip(self, ip: str, dry_run: bool = True, allowlist: Optional[list] = None) -> Tuple[bool, str, str]:
        """
        Attempt to block an IP address.
        
        Returns:
            Tuple[bool, str, str]: (Success, Message, RuleReference)
        """
        # Step 1: Validate IP and safe-to-block constraints
        safe, reason = is_safe_to_block(ip, allowlist)
        if not safe:
            logger.warning("Refusing to block IP %s: %s", ip, reason)
            return False, f"Safety restriction: {reason}", ""

        # Step 2: If dry_run is true or real blocking disabled
        if dry_run or not self.real_enabled:
            mode_desc = "SIMULATED / DRY-RUN" if dry_run else "SIMULATED (Linux iptables disabled or non-Linux OS)"
            logger.info("[%s] Block registered for IP: %s", mode_desc, ip)
            rule_ref = f"simulated_rule_{ip}"
            return True, f"Successfully executed {mode_desc} block for {ip}", rule_ref

        # Step 3: Real Linux iptables execution with explicit argument lists
        # Checks if already present first
        if self._rule_exists(ip):
            return True, f"Rule already active in iptables for {ip}", f"iptables_rule_{ip}"

        cmd = [
            "iptables", "-I", "INPUT",
            "-s", ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment", RULE_TAG
        ]

        try:
            logger.info("Executing firewall command: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                shell=False
            )
            if proc.returncode == 0:
                logger.info("Real firewall block applied successfully for %s", ip)
                return True, f"Firewall rule added for {ip}", f"iptables_rule_{ip}"
            else:
                err_msg = proc.stderr.strip() or "Unknown error"
                logger.error("iptables failed with code %d: %s", proc.returncode, err_msg)
                return False, f"Firewall error: {err_msg}", ""
        except FileNotFoundError:
            logger.error("iptables binary not found on system.")
            return False, "iptables executable not found", ""
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out")
            return False, "Firewall command timed out", ""
        except Exception as ex:
            logger.exception("Unexpected error executing iptables: %s", ex)
            return False, f"Internal execution error: {str(ex)}", ""

    def unblock_ip(self, ip: str, dry_run: bool = True) -> Tuple[bool, str]:
        """
        Attempt to remove an IP block.
        """
        addr = validate_ip(ip)
        if not addr:
            return False, "Invalid IP format"

        if dry_run or not self.real_enabled:
            logger.info("[SIMULATED] Unblock applied for IP: %s", ip)
            return True, f"Simulated unblock applied for {ip}"

        # Delete rule from iptables using exact match
        cmd = [
            "iptables", "-D", "INPUT",
            "-s", ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment", RULE_TAG
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                shell=False
            )
            if proc.returncode == 0:
                logger.info("Firewall rule removed successfully for %s", ip)
                return True, f"Firewall rule removed for {ip}"
            else:
                err = proc.stderr.strip()
                logger.warning("iptables unblock returned code %d: %s", proc.returncode, err)
                return False, f"Failed to remove rule: {err}"
        except Exception as ex:
            logger.exception("Error unblocking IP %s: %s", ip, ex)
            return False, str(ex)

    def _rule_exists(self, ip: str) -> bool:
        """Check if an existing silent_witness_block rule matches this IP."""
        if not self.real_enabled:
            return False
        cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", RULE_TAG]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=False)
            return proc.returncode == 0
        except Exception:
            return False


_firewall_instance: Optional[FirewallManager] = None


def get_firewall() -> FirewallManager:
    global _firewall_instance
    if _firewall_instance is None:
        _firewall_instance = FirewallManager()
    return _firewall_instance
