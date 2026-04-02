#!/usr/bin/env python3
"""
airmon-nx v2.0
A modern Python replacement for airmon-ng — stdlib only, no external deps.

Features:
  - Full feature parity with airmon-ng
  - JSON state management in /run/airmon-nx
  - Targeted per-interface process killing vs global kill-all
  - rfkill detection, unblocking, VM-aware guidance
  - Driver detection, normalization, quirk-aware mode switching
  - Chipset ID via lsusb/lspci/sdio tables
  - Channel/frequency validation against hardware capabilities
  - Kernel breakage detection (e.g. 5.15 radiotap bug)
  - Lost phy recovery
  - Raspberry Pi wireless detection
  - Interface name length enforcement (15 char Linux limit)
  - Rich ncurses TUI with live refresh

Usage:
  airmon-nx list                          List wireless interfaces
  airmon-nx check [iface]                 Show conflicting processes
  airmon-nx check --kill <iface>          Kill only processes bound to <iface>
  airmon-nx check --kill-all              Kill ALL interfering processes globally
  airmon-nx start <iface> [channel]       Enable monitor mode
  airmon-nx stop <iface>                  Disable monitor mode
  airmon-nx ui                            ncurses interface monitor
"""

import argparse
import curses
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

# ═══════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════

VERSION = "2.0.0"
STATE_DIR = Path("/run/airmon-nx")
IW_SOURCE = "https://mirrors.edge.kernel.org/pub/software/network/iw/iw-5.9.tar.xz"

REQUIRED_TOOLS = ["iw", "ip"]
RECOMMENDED_TOOLS = ["ethtool", "lsusb", "lspci", "rfkill", "modinfo"]

INTERFERING_PROCESSES = [
    "wpa_supplicant", "wpa_action", "wpa_cli",
    "dhclient", "ifplugd", "dhcdbd", "dhcpcd", "udhcpc",
    "NetworkManager", "knetworkmanager",
    "avahi-autoipd", "avahi-daemon",
    "wlassistant", "wifibox", "net_applet",
    "wicd-daemon", "wicd-client",
    "iwd",
]

INTERFERING_SERVICES = [
    "NetworkManager", "network-manager",
    "avahi-daemon", "wicd", "iwd",
]

# drivers that CANNOT create virtual monitor interfaces —
# they require direct type conversion on the base interface
NO_VIF_DRIVERS = frozenset({
    "88XXau", "icnss",
})

# drivers where we KNOW vif won't work based on iw reporting
# "interface combinations are not supported" — checked at runtime too
NO_VIF_HINT_DRIVERS = frozenset({
    "8812au", "8814au", "rtl88xxau", "rtl88XXau",
})

DRIVER_ALIASES = {
    "rt2870":      "rt2870sta",
    "rtl8187L":    "r8187l",
    "8812au":      "88XXau",
    "8814au":      "88XXau",
    "rtl88xxau":   "88XXau",
    "rtl88XXau":   "88XXau",
    "rtl8812au":   "8812au",
}

# vendor driver recommendations keyed by (driver, min_kernel_major, min_kernel_minor)
DRIVER_RECOMMENDATIONS = {
    "rt2870sta":  (2, 6, 35, "rt2800usb"),
    "rt3070sta":  (2, 6, 35, "rt2800usb"),
    "rt5390sta":  (2, 6, 39, "rt2800usb"),
    "ar9170usb":  (2, 6, 37, "carl9170"),
    "arusb_lnx":  (2, 6, 37, "carl9170"),
    "r8187":      (2, 6, 29, "rtl8187"),
    "r8187l":     (2, 6, 29, "rtl8187"),
}

SDIO_CHIPSETS = {
    "0x02d0:0x4330": "Broadcom 4330",
    "0x02d0:0x4329": "Broadcom 4329",
    "0x02d0:0x4334": "Broadcom 4334",
    "0x02d0:0xa94c": "Broadcom 43340",
    "0x02d0:0xa94d": "Broadcom 43341",
    "0x02d0:0x4324": "Broadcom 43241",
    "0x02d0:0x4335": "Broadcom 4335/4339",
    "0x02d0:0xa962": "Broadcom 43362",
    "0x02d0:0xa9a6": "Broadcom 43430",
    "0x02d0:0x4345": "Broadcom 43455",
    "0x02d0:0x4354": "Broadcom 4354",
    "0x02d0:0xa887": "Broadcom 43143",
}

# Raspberry Pi revision codes with onboard wireless
RPI_WIRELESS_REVISIONS = frozenset({
    "a22082", "a32082", "a52082", "a02082", "9000c1",
    "a020d3", "9020e0", "a22083", "a020a0", "a220a0",
    "a02100", "a03111", "b03111", "c03111", "b03112",
    "b03114", "c03112", "c03114", "d03114", "c03130",
    "a03140", "b03140", "c03140", "d03140",
})

# ═══════════════════════════════════════════════
#  LOW-LEVEL HELPERS
# ═══════════════════════════════════════════════

def run(cmd, timeout=10):
    """Run a command, return (ok, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout,
        )
        return p.returncode == 0, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "command timed out"
    except Exception as e:
        return False, "", str(e)


def run_rc(cmd):
    """Run a command, return just the return code."""
    try:
        return subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode
    except Exception:
        return -1


def tool_exists(name):
    return shutil.which(name) is not None


def read_sysfs(path):
    """Read a sysfs file, return stripped content or None."""
    try:
        return Path(path).read_text().strip()
    except Exception:
        return None


def write_sysfs(path, value):
    """Write to a sysfs file. Returns True on success."""
    try:
        Path(path).write_text(str(value))
        return True
    except Exception:
        return False


def is_root():
    return os.getuid() == 0


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# ═══════════════════════════════════════════════
#  SYSTEM DETECTION
# ═══════════════════════════════════════════════

class SystemInfo:
    """Gather and cache system-level information."""

    def __init__(self):
        self._kernel_version = None
        self._kv_major = None
        self._kv_minor = None
        self._kv_patch = None
        self._vm_type = None
        self._vm_source = None
        self._vm_checked = False
        self._tool_cache = {}
        self._rpi_revision = None

    # ── kernel ──

    @property
    def kernel_version(self):
        if self._kernel_version is None:
            self._parse_kernel()
        return self._kernel_version

    @property
    def kv_major(self):
        if self._kv_major is None:
            self._parse_kernel()
        return self._kv_major

    @property
    def kv_minor(self):
        if self._kv_minor is None:
            self._parse_kernel()
        return self._kv_minor

    @property
    def kv_patch(self):
        if self._kv_patch is None:
            self._parse_kernel()
        return self._kv_patch

    def _parse_kernel(self):
        # ubuntu puts real version in version_signature
        sig = read_sysfs("/proc/version_signature")
        if sig:
            parts = sig.split()
            kv = parts[2] if len(parts) >= 3 else parts[-1]
        else:
            ok, out, _ = run(["uname", "-r"])
            kv = out.split("-")[0] if ok else "0.0.0"

        self._kernel_version = kv
        pieces = kv.split(".")
        try:
            self._kv_major = int(pieces[0]) if len(pieces) > 0 else 0
            self._kv_minor = int(pieces[1]) if len(pieces) > 1 else 0
            self._kv_patch = int(pieces[2]) if len(pieces) > 2 else 0
        except ValueError:
            self._kv_major = 0
            self._kv_minor = 0
            self._kv_patch = 0

        # debian derivatives report 0 patch in uname -r, real version in uname -v
        if self._kv_patch == 0:
            ok, out, _ = run(["uname", "-v"])
            if ok:
                m = re.search(r'(\d+\.\d+\.(\d+))', out)
                if m:
                    try:
                        self._kv_patch = int(m.group(2))
                    except ValueError:
                        pass

    def kernel_at_least(self, major, minor, patch=0):
        return (self.kv_major, self.kv_minor, self.kv_patch) >= (major, minor, patch)

    def check_kernel_breakage(self):
        warnings = []
        if (self.kv_major == 5 and self.kv_minor == 15
                and self.kv_patch < 5):
            warnings.append(
                "WARNING: Kernel 5.15.0-5.15.4 has broken radiotap headers.\n"
                "  Packet capture tools will not work correctly.\n"
                "  Fixed in kernel 5.15.5+."
            )
        return warnings

    # ── tool availability ──

    def has_tool(self, name):
        if name not in self._tool_cache:
            self._tool_cache[name] = tool_exists(name)
        return self._tool_cache[name]

    # ── VM detection (ported from airmon-ng) ──

    @property
    def vm_type(self):
        if not self._vm_checked:
            self._detect_vm()
        return self._vm_type

    @property
    def vm_source(self):
        if not self._vm_checked:
            self._detect_vm()
        return self._vm_source

    def _detect_vm(self):
        self._vm_checked = True

        checks = [
            self._vm_from_lsmod,
            self._vm_from_scsi,
            self._vm_from_ide,
            self._vm_from_lspci,
            self._vm_from_lscpu,
            self._vm_from_devvmnet,
            self._vm_from_dmi,
            self._vm_from_dmesg,
        ]
        for check in checks:
            result = check()
            if result:
                self._vm_type, self._vm_source = result
                return

    def _vm_from_lsmod(self):
        if not self.has_tool("lsmod"):
            return None
        ok, out, _ = run(["lsmod"])
        if not ok or not out:
            return None
        patterns = [
            (r"vboxsf|vboxguest", "VirtualBox"),
            (r"vmw_ballon|vmxnet|vmw", "VMware"),
            (r"xen-vbd|xen-vnif", "Xen"),
            (r"virtio_pci|virtio_net", "Qemu/KVM"),
            (r"hv_vmbus|hv_blkvsc|hv_netvsc|hv_utils|hv_storvsc", "MS Hyper-V"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, out, re.IGNORECASE):
                return name, "lsmod"
        return None

    def _vm_from_scsi(self):
        scsi = read_sysfs("/proc/scsi/scsi")
        if not scsi:
            return None
        sl = scsi.lower()
        if "vmware" in sl:
            return "VMware", "/proc/scsi/scsi"
        if "vbox" in sl:
            return "VirtualBox", "/proc/scsi/scsi"
        return None

    def _vm_from_ide(self):
        ide_dir = Path("/proc/ide")
        if not ide_dir.is_dir():
            return None
        for model_file in ide_dir.glob("hd*/model"):
            model = (read_sysfs(str(model_file)) or "").lower()
            if "vbox" in model:
                return "VirtualBox", "ide_model"
            if "vmware" in model:
                return "VMware", "ide_model"
            if "qemu" in model:
                return "Qemu/KVM", "ide_model"
            if re.search(r"virtual (hd|cd)", model):
                return "Hyper-V/Virtual PC", "ide_model"
        return None

    def _vm_from_lspci(self):
        if not self.has_tool("lspci"):
            return None
        ok, out, _ = run(["lspci"])
        if not ok:
            return None
        ol = out.lower()
        if "vmware" in ol:
            return "VMware", "lspci"
        if "virtualbox" in ol:
            return "VirtualBox", "lspci"
        return None

    def _vm_from_lscpu(self):
        if not self.has_tool("lscpu"):
            return None
        ok, out, _ = run(["lscpu"])
        if not ok:
            return None
        ol = out.lower()
        if "xen" in ol:
            return "Xen", "lscpu"
        if "microsoft" in ol:
            return "MS Hyper-V", "lscpu"
        return None

    def _vm_from_devvmnet(self):
        if Path("/dev/vmnet").exists():
            return "VMware", "/dev/vmnet"
        return None

    def _vm_from_dmi(self):
        if not self.has_tool("dmidecode"):
            return None
        ok, out, _ = run(["dmidecode"])
        if not ok:
            return None
        ol = out.lower()
        for needle, name in [("microsoft corporation", "MS Hyper-V"),
                              ("vmware", "VMware"), ("virtualbox", "VirtualBox"),
                              ("qemu", "Qemu/KVM"), ("domu", "Xen")]:
            if needle in ol:
                return name, "dmidecode"
        return None

    def _vm_from_dmesg(self):
        if not self.has_tool("dmesg"):
            return None
        ok, out, _ = run(["dmesg"], timeout=5)
        if not ok:
            return None
        ol = out.lower()
        patterns = [
            (r"vboxbios|vboxcput|vboxfacp|vboxxsdt|vbox cd-rom|vbox harddisk", "VirtualBox"),
            (r"vmware virtual ide|vmware pvscsi|vmware virtual platform", "VMware"),
            (r"xen_mem|xen-vbd", "Xen"),
            (r"qemu virtual cpu version", "Qemu/KVM"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, ol):
                return name, "dmesg"
        return None

    # ── Raspberry Pi detection ──

    @property
    def rpi_revision(self):
        if self._rpi_revision is None:
            cpuinfo = read_sysfs("/proc/cpuinfo")
            if cpuinfo:
                m = re.search(r"Revision\s*:\s*(\S+)", cpuinfo)
                self._rpi_revision = m.group(1) if m else ""
            else:
                self._rpi_revision = ""
        return self._rpi_revision

    @property
    def is_rpi_wireless(self):
        return self.rpi_revision in RPI_WIRELESS_REVISIONS

# ═══════════════════════════════════════════════
#  RFKILL
# ═══════════════════════════════════════════════

class RfkillManager:
    """Handle rfkill soft/hard block detection and unblocking."""

    def __init__(self, sysinfo):
        self.available = (
            sysinfo.has_tool("rfkill")
            and Path("/dev/rfkill").exists()
        )
        self.sysinfo = sysinfo

    def get_index_for_phy(self, phy):
        if not self.available:
            return None
        ok, out, _ = run(["rfkill", "list"])
        if not ok:
            return None
        for line in out.splitlines():
            if phy + ":" in line:
                m = re.match(r"(\d+):", line)
                if m:
                    return m.group(1)
        return None

    def check(self, phy):
        """Returns (soft_blocked, hard_blocked) or None."""
        if not self.available:
            return None
        index = self.get_index_for_phy(phy)
        if index is None:
            return None
        ok, out, _ = run(["rfkill", "list", index])
        if not ok or not out:
            return None
        soft = hard = False
        for line in out.splitlines():
            ll = line.lower()
            if "soft" in ll and "yes" in ll:
                soft = True
            if "hard" in ll and "yes" in ll:
                hard = True
        return (soft, hard)

    def unblock(self, phy):
        if not self.available:
            return False
        index = self.get_index_for_phy(phy)
        phy_num = phy.replace("phy", "")
        ok, _, _ = run(["rfkill", "unblock", phy_num])
        if not ok and index:
            ok, _, _ = run(["rfkill", "unblock", index])
        if ok:
            time.sleep(1)
        return ok

    def describe_block(self, phy):
        """Return (is_blocked, description_string) or None."""
        status = self.check(phy)
        if status is None:
            return None
        soft, hard = status
        if not soft and not hard:
            return None
        index = self.get_index_for_phy(phy) or "?"
        lines = []
        if soft and hard:
            lines.append(f"  {phy}: soft + hard blocked")
            lines.append(f"  Flip hardware switch AND run: rfkill unblock {index}")
        elif hard:
            lines.append(f"  {phy}: hard blocked")
            lines.append("  Flip hardware WiFi switch or check BIOS.")
            lines.append(f"  Also try: rfkill unblock {index}")
            if self.sysinfo.vm_type:
                lines.append(f"  Detected VM: {self.sysinfo.vm_type} (via {self.sysinfo.vm_source})")
                lines.append("  Some VMs force rfkill hard block — try bare metal.")
        elif soft:
            lines.append(f"  {phy}: soft blocked")
            lines.append(f"  Run: rfkill unblock {index}")
        return True, "\n".join(lines)

# ═══════════════════════════════════════════════
#  INTERFACE DISCOVERY & DETAILS
# ═══════════════════════════════════════════════

class WirelessInterface:
    """Represents a single wireless interface with all detected metadata."""

    def __init__(self, name):
        self.name = name
        self.phy = None
        self.driver = None
        self.driver_raw = None
        self.bus = None
        self.bus_info = None
        self.device_id = None
        self.chipset = None
        self.firmware = None
        self.stack = None
        self.mac80211 = False
        self.iface_type = None
        self.net_type = None
        self.connected = False
        self.extended = None
        self.from_source = "K"
        self.rfkill_status = None

    @property
    def is_monitor(self):
        return self.net_type == "803" or self.iface_type == "monitor"

    @property
    def is_managed(self):
        return self.net_type == "1" or self.iface_type == "managed"

    @property
    def mode_str(self):
        if self.is_monitor:
            return "monitor"
        if self.is_managed:
            return "managed"
        if self.net_type:
            return f"type:{self.net_type}"
        if self.iface_type:
            return self.iface_type
        return "unknown"


def discover_interfaces(sysinfo):
    """Discover all wireless interfaces. Returns list of WirelessInterface."""
    ifaces = {}

    # method 1: sysfs DEVTYPE=wlan
    net_dir = Path("/sys/class/net")
    if net_dir.is_dir():
        for entry in sorted(net_dir.iterdir()):
            uevent = entry / "uevent"
            if uevent.is_file():
                content = read_sysfs(str(uevent)) or ""
                if "DEVTYPE=wlan" in content:
                    ifaces[entry.name] = True

    # method 2: iw dev
    ok, out, _ = run(["iw", "dev"])
    if ok:
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("Interface"):
                ifaces[stripped.split()[1]] = True

    result = []
    for name in sorted(ifaces.keys()):
        wi = WirelessInterface(name)
        _populate_interface(wi, sysinfo)
        result.append(wi)
    return result


def _populate_interface(wi, sysinfo):
    """Fill all metadata for a WirelessInterface."""
    name = wi.name

    # ── stack ──
    phy_dir = Path(f"/sys/class/net/{name}/phy80211")
    if phy_dir.is_dir():
        wi.mac80211 = True
        wi.stack = "mac80211"
    else:
        wi.mac80211 = False
        wi.stack = "ieee80211"
    if Path(f"/proc/sys/dev/{name}/fftxqmin").exists():
        wi.mac80211 = False
        wi.stack = "net80211"

    # ── phy ──
    phy_name_file = Path(f"/sys/class/net/{name}/phy80211/name")
    if phy_name_file.is_file():
        wi.phy = read_sysfs(str(phy_name_file))
    elif phy_dir.is_dir():
        try:
            wi.phy = phy_dir.resolve().name
        except Exception:
            pass
    if not wi.phy and not wi.mac80211:
        wi.phy = "null"

    # ── net type ──
    type_file = Path(f"/sys/class/net/{name}/type")
    if type_file.is_file():
        wi.net_type = read_sysfs(str(type_file))

    # ── ethtool ──
    ethtool_output = ""
    if sysinfo.has_tool("ethtool"):
        ok, out, _ = run(["ethtool", "-i", name])
        if ok:
            ethtool_output = out

    # ── bus ──
    modalias_file = Path(f"/sys/class/net/{name}/device/modalias")
    if modalias_file.is_file():
        modalias = read_sysfs(str(modalias_file)) or ""
        wi.bus = modalias.split(":")[0] if ":" in modalias else None

    # ── driver ──
    _detect_driver(wi, ethtool_output, sysinfo)

    # ── chipset ──
    _detect_chipset(wi, ethtool_output, sysinfo)

    # ── firmware ──
    if ethtool_output:
        m = re.search(r"firmware-version:\s*(\S+)", ethtool_output)
        if m and m.group(1) != "N/A":
            wi.firmware = m.group(1)

    # ── from (driver source) ──
    _detect_from(wi, sysinfo)

    # ── connection status ──
    ok, out, _ = run(["iw", "dev", name, "link"])
    if ok and "Connected to" in out:
        wi.connected = True

    # ── iw type ──
    ok, out, _ = run(["iw", "dev", name, "info"])
    if ok:
        m = re.search(r"type\s+(\S+)", out)
        if m:
            wi.iface_type = m.group(1)

    # ── extended info ──
    _detect_extended(wi, sysinfo)


def _detect_driver(wi, ethtool_output, sysinfo):
    name = wi.name
    driver = None

    uevent = Path(f"/sys/class/net/{name}/device/uevent")
    if uevent.is_file():
        content = read_sysfs(str(uevent)) or ""
        m = re.search(r"DRIVER=(\S+)", content)
        if m:
            driver = m.group(1)

    if driver == "usb" and ethtool_output:
        m = re.search(r"bus-info:\s*(\S+)", ethtool_output)
        if m:
            busaddr = m.group(1) + ":1.0"
            sub_uevent = Path(f"/sys/class/net/{name}/device/{busaddr}/uevent")
            if sub_uevent.is_file():
                content = read_sysfs(str(sub_uevent)) or ""
                m2 = re.search(r"DRIVER=(\S+)", content)
                if m2:
                    driver = m2.group(1)
        if driver == "rt2870":
            driver = "rt2870sta"
        prod = read_sysfs(f"/sys/class/net/{name}/device/idProduct")
        if prod == "3070":
            driver = "rt3070sta"

    if driver == "rtl8187" and wi.stack == "ieee80211":
        driver = "r8187"

    wi.driver_raw = driver
    if driver in DRIVER_ALIASES:
        driver = DRIVER_ALIASES[driver]

    if driver and sysinfo.has_tool("modinfo"):
        rc = run_rc(["modinfo", "-F", "filename", driver])
        if rc != 0:
            if wi.device_id and wi.bus == "pci" and sysinfo.has_tool("lspci"):
                ok, out, _ = run(["lspci", "-d", wi.device_id, "-k"])
                if ok:
                    m = re.search(r"modules:\s*(\S+)", out, re.IGNORECASE)
                    if m:
                        driver = m.group(1)

    wi.driver = driver or "??????"


def _detect_chipset(wi, ethtool_output, sysinfo):
    name = wi.name
    chipset = None
    device_id = None

    modalias_file = Path(f"/sys/class/net/{name}/device/modalias")

    if modalias_file.is_file():
        modalias = read_sysfs(str(modalias_file)) or ""

        if wi.bus == "usb" and sysinfo.has_tool("lsusb"):
            m = re.search(r"usb:v([0-9A-Fa-f]{4})p([0-9A-Fa-f]{4})", modalias)
            if m:
                bus_info_colon = f"{m.group(1)}:{m.group(2)}"
                ok, out, _ = run(["lsusb", "-d", bus_info_colon])
                if ok and out:
                    parts = out.split(":", 2)
                    if len(parts) >= 3:
                        chipset = parts[2].strip()
                        for suffix in [" Network Connection", " Wireless Adapter"]:
                            chipset = chipset.replace(suffix, "")

        elif wi.bus in ("pci", "pcmcia") and sysinfo.has_tool("lspci"):
            vendor_file = Path(f"/sys/class/net/{name}/device/vendor")
            device_file = Path(f"/sys/class/net/{name}/device/device")

            if vendor_file.is_file() and device_file.is_file():
                vendor = (read_sysfs(str(vendor_file)) or "").replace("0x", "")
                device = (read_sysfs(str(device_file)) or "").replace("0x", "")
                device_id = f"{vendor}:{device}"
                ok, out, _ = run(["lspci", "-d", device_id])
                if ok and out:
                    parts = out.split(":", 2)
                    if len(parts) >= 3:
                        chipset = parts[2].strip()
                        for s in ["Wireless LAN Controller ", " Network Connection",
                                  " Wireless Adapter"]:
                            chipset = chipset.replace(s, "")
            else:
                if ethtool_output:
                    m = re.search(r"bus-info:\s*\S*:(\S+)", ethtool_output)
                    if m:
                        bus_addr = m.group(1)
                        ok, out, _ = run(["lspci"])
                        if ok:
                            for line in out.splitlines():
                                if bus_addr in line:
                                    parts = line.split(":", 2)
                                    if len(parts) >= 3:
                                        chipset = parts[2].strip()
                                    break

        elif wi.bus == "sdio":
            vendor = read_sysfs(f"/sys/class/net/{name}/device/vendor")
            device = read_sysfs(f"/sys/class/net/{name}/device/device")
            if vendor and device:
                device_id = f"{vendor}:{device}"
                chipset = SDIO_CHIPSETS.get(device_id,
                                            f"Unknown SDIO device {device_id}")

    # fallback: idVendor/idProduct directly
    if chipset is None:
        vid_file = Path(f"/sys/class/net/{name}/device/idVendor")
        pid_file = Path(f"/sys/class/net/{name}/device/idProduct")
        if vid_file.is_file() and pid_file.is_file():
            vid = read_sysfs(str(vid_file))
            pid = read_sysfs(str(pid_file))
            if vid and pid and sysinfo.has_tool("lsusb"):
                device_id = f"{vid}:{pid}"
                ok, out, _ = run(["lsusb", "-d", device_id])
                if ok and out:
                    parts = out.split(":", 2)
                    if len(parts) >= 3:
                        chipset = parts[2].strip()
                        for s in [" Network Connection", " Wireless Adapter"]:
                            chipset = chipset.replace(s, "")

    if chipset is None and wi.driver == "mac80211_hwsim":
        chipset = "Software simulator of 802.11 radio(s) for mac80211"

    if chipset is None and ethtool_output:
        m = re.search(r"bus-info:\s*(\S*bcma\S*)", ethtool_output)
        if m:
            wi.bus = "bcma"
            if wi.driver in ("brcmsmac", "brcmfmac", "b43"):
                chipset = "Broadcom on bcma bus (limited info)"
            else:
                chipset = f"Unknown driver '{wi.driver}' on bcma bus"

    wi.chipset = chipset or "unknown chipset"
    if device_id:
        wi.device_id = device_id


def _detect_from(wi, sysinfo):
    if not sysinfo.has_tool("modinfo"):
        wi.from_source = "K"
        return
    ok, out, _ = run(["modinfo", "-F", "filename", wi.driver])
    if not ok:
        wi.from_source = "K"
        return
    vendor_in_kernel = {"r8187", "r8187l", "rt5390sta", "8812au", "8814au"}
    if wi.driver in vendor_in_kernel:
        wi.from_source = "V"
        return
    if "kernel/drivers" in out:
        wi.from_source = "K"
    elif "updates/drivers" in out:
        wi.from_source = "C"
    elif "misc" in out:
        wi.from_source = "V"
    elif "staging" in out:
        wi.from_source = "S"
    else:
        wi.from_source = "?"


def _detect_extended(wi, sysinfo):
    lines = []

    rfk = RfkillManager(sysinfo)
    status = rfk.check(wi.phy)
    if status:
        soft, hard = status
        if soft and hard:
            lines.append("rfkill: hard+soft blocked")
        elif hard:
            lines.append("rfkill: hard blocked")
        elif soft:
            lines.append("rfkill: soft blocked")

    if wi.driver == "??????":
        lines.append("driver detection failed — please report")

    product = read_sysfs(f"/sys/class/net/{wi.name}/device/product")
    if product:
        lines.append(product)

    if wi.driver == "wl":
        if Path("/proc/brcm_monitor0").exists():
            lines.append("experimental wl monitor support")
        else:
            lines.append("no known monitor support — try b43")

    if wi.driver == "brcmsmac":
        lines.append("brcm80211 — no injection support")

    if wi.driver == "r8712u":
        lines.append("no monitor or injection support")

    if wi.driver in DRIVER_RECOMMENDATIONS:
        req_maj, req_min, req_pat, replacement = DRIVER_RECOMMENDATIONS[wi.driver]
        if sysinfo.kernel_at_least(req_maj, req_min, req_pat):
            lines.append(f"blacklist {wi.driver} and use {replacement}")
        else:
            lines.append(f"upgrade to {req_maj}.{req_min}.{req_pat}+ for {replacement}")

    if not lines:
        lines.append(wi.mode_str)

    wi.extended = " | ".join(lines)


def discover_lost_phys():
    """Find phys with no interfaces assigned."""
    lost = []
    ieee_dir = Path("/sys/class/ieee80211")
    if ieee_dir.is_dir():
        for phy_dir in sorted(ieee_dir.iterdir()):
            net_dir = phy_dir / "device" / "net"
            if not net_dir.is_dir():
                lost.append(phy_dir.name)
            elif not any(net_dir.iterdir()):
                lost.append(phy_dir.name)
    return lost

# ═══════════════════════════════════════════════
#  PROCESS / SERVICE MANAGEMENT
# ═══════════════════════════════════════════════

def find_interfering_processes():
    """Find all interfering processes. Returns list of dicts with pid, name, cmdline, interfaces."""
    results = []

    ok, out, _ = run(["ps", "-eo", "pid,comm"])
    if not ok:
        ok, out, _ = run(["ps"])
        if not ok:
            return results

    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        comm = parts[1].strip()

        if any(p == comm or p in comm for p in INTERFERING_PROCESSES):
            cmdline = read_sysfs(f"/proc/{pid}/cmdline")
            if cmdline:
                cmdline = cmdline.replace("\x00", " ").strip()
            else:
                cmdline = comm

            bound_ifaces = _find_process_interfaces(pid, cmdline)
            results.append({
                "pid": pid,
                "name": comm,
                "cmdline": cmdline,
                "interfaces": bound_ifaces,
            })

    return results


def _find_process_interfaces(pid, cmdline):
    """Determine which wireless interfaces a process is bound to."""
    bound = set()
    tokens = cmdline.split()

    for i, tok in enumerate(tokens):
        if tok in ("-i", "--interface", "-D") and i + 1 < len(tokens):
            candidate = tokens[i + 1]
            if Path(f"/sys/class/net/{candidate}").exists():
                bound.add(candidate)
        elif Path(f"/sys/class/net/{tok}").exists():
            uevent = read_sysfs(f"/sys/class/net/{tok}/uevent")
            if uevent and "DEVTYPE=wlan" in uevent:
                bound.add(tok)

    # NetworkManager: check which wifi devices it manages
    if "NetworkManager" in cmdline and tool_exists("nmcli"):
        ok, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
        if ok:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] == "wifi":
                    bound.add(parts[0])

    return sorted(bound)


def find_processes_for_interface(iface):
    """Split interfering processes into targeted (bound to iface) and untargeted."""
    all_procs = find_interfering_processes()
    targeted = []
    untargeted = []

    for proc in all_procs:
        if iface in proc["interfaces"]:
            targeted.append(proc)
        elif not proc["interfaces"]:
            proc["ambiguous"] = True
            targeted.append(proc)
        else:
            untargeted.append(proc)

    return targeted, untargeted


def kill_process(pid):
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return True
    except PermissionError:
        return False


def stop_service(service_name):
    for cmd_name in ["systemctl", "service", "rc-service"]:
        if tool_exists(cmd_name):
            if cmd_name == "systemctl":
                args = [cmd_name, "stop", service_name]
            else:
                args = [cmd_name, service_name, "stop"]
            for attempt in range(5):
                if run_rc(args) == 0:
                    return True
                time.sleep(0.5)
    return False


def stop_services_for_interface(iface):
    """Targeted kill: stop only services/processes bound to this interface."""
    stopped = []

    # tell NM to stop managing this specific device
    if tool_exists("nmcli"):
        ok, out, _ = run(["nmcli", "-t", "-f", "DEVICE,STATE", "device"])
        if ok:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[0] == iface:
                    if parts[1] not in ("unmanaged", "unavailable"):
                        run(["nmcli", "device", "set", iface, "managed", "no"])
                        stopped.append(f"NetworkManager (unmanaged {iface})")

    # kill processes bound to this interface
    procs = find_interfering_processes()
    for proc in procs:
        if iface in proc["interfaces"]:
            if kill_process(proc["pid"]):
                stopped.append(f"{proc['name']} (pid {proc['pid']})")

    return stopped


def stop_all_services():
    """Global kill: stop ALL interfering services and processes."""
    stopped = []

    for svc in INTERFERING_SERVICES:
        if stop_service(svc):
            stopped.append(f"service: {svc}")

    time.sleep(0.5)
    procs = find_interfering_processes()
    for proc in procs:
        if kill_process(proc["pid"]):
            stopped.append(f"{proc['name']} (pid {proc['pid']})")

    return stopped

# ═══════════════════════════════════════════════
#  CHANNEL / FREQUENCY
# ═══════════════════════════════════════════════

def get_supported_channels(phy):
    ok, out, _ = run(["iw", "phy", phy, "info"])
    if not ok:
        return []
    return [int(m.group(1)) for m in re.finditer(r"\[(\d+)\]", out)
            if m.group(1).isdigit()]


def get_supported_frequencies(phy):
    ok, out, _ = run(["iw", "phy", phy, "info"])
    if not ok:
        return []
    return [int(m.group(1)) for m in re.finditer(r"(\d+)\s+MHz", out)
            if m.group(1).isdigit()]


def validate_and_set_channel(iface, phy, channel):
    """Validate and set channel/freq. Returns (success, message_or_none)."""
    if channel is None:
        return True, None
    try:
        ch = int(channel)
    except ValueError:
        return False, f"Invalid channel/frequency: {channel}"

    run(["ip", "link", "set", iface, "up"])

    if ch < 1000:
        supported = get_supported_channels(phy)
        if supported and ch not in supported:
            return False, (
                f"Channel {ch} not supported by {iface}.\n"
                f"  Supported: {', '.join(map(str, sorted(supported)))}"
            )
        ok, _, err = run(["iw", "dev", iface, "set", "channel", str(ch)])
    else:
        supported = get_supported_frequencies(phy)
        if supported and ch not in supported:
            return False, (
                f"Frequency {ch} MHz not supported by {iface}.\n"
                f"  Supported: {', '.join(map(str, sorted(supported)))}"
            )
        ok, _, err = run(["iw", "dev", iface, "set", "freq", str(ch)])

    if not ok:
        msg = f"Error setting channel/frequency {ch}: {err}"
        if "(-16)" in err:
            msg += "\n  Error -16: card likely reverted to station mode."
        if "(-22)" in err:
            msg += "\n  Likely outside regulatory domain."
        return False, msg

    return True, None

# ═══════════════════════════════════════════════
#  MONITOR MODE OPERATIONS
# ═══════════════════════════════════════════════

def _phy_supports_vif(phy, driver):
    if driver in NO_VIF_DRIVERS or driver in NO_VIF_HINT_DRIVERS:
        return False
    ok, out, _ = run(["iw", "phy", phy, "info"])
    if ok and "interface combinations are not supported" in out:
        return False
    return True


def _existing_monitor_on_phy(phy):
    net_dir = Path(f"/sys/class/ieee80211/{phy}/device/net")
    if net_dir.is_dir():
        for entry in net_dir.iterdir():
            type_file = entry / "type"
            if type_file.is_file() and read_sysfs(str(type_file)) == "803":
                return entry.name
    return None


def _find_free_interface_name(suffix="mon"):
    for i in range(100):
        base = f"wlan{i}"
        candidate = f"{base}{suffix}" if suffix else base
        base_exists = Path(f"/sys/class/net/{base}").exists()
        cand_exists = Path(f"/sys/class/net/{candidate}").exists()
        if suffix:
            if not base_exists and not cand_exists:
                return candidate
        else:
            if not base_exists:
                return base
    return None


def _resolve_created_name(phy, target_type="803"):
    net_dir = Path(f"/sys/class/ieee80211/{phy}/device/net")
    if net_dir.is_dir():
        for entry in net_dir.iterdir():
            type_file = entry / "type"
            if type_file.is_file() and read_sysfs(str(type_file)) == target_type:
                return entry.name
    return None


def start_monitor(iface_name, channel=None, sysinfo=None):
    """Enable monitor mode. Returns (success, monitor_name, messages)."""
    if sysinfo is None:
        sysinfo = SystemInfo()

    msgs = []
    ifaces = discover_interfaces(sysinfo)
    wi = None
    for i in ifaces:
        if i.name == iface_name:
            wi = i
            break

    if wi is None:
        return False, None, [f"Interface {iface_name} not found."]

    phy = wi.phy
    driver = wi.driver

    if not phy or phy == "null":
        return False, None, [f"Cannot determine phy for {iface_name}. Not mac80211?"]

    msgs.append(f"PHY: {phy}  Driver: {driver}  Chipset: {wi.chipset}")

    # ── rfkill ──
    rfk = RfkillManager(sysinfo)
    rfk_result = rfk.describe_block(phy)
    if rfk_result:
        blocked, desc = rfk_result
        if blocked:
            msgs.append(desc)
            msgs.append("Attempting automatic rfkill unblock...")
            if rfk.unblock(phy):
                status = rfk.check(phy)
                if status and (status[0] or status[1]):
                    msgs.append("Unblock failed. Cannot proceed.")
                    return False, None, msgs
                msgs.append("Unblock succeeded.")
            else:
                msgs.append("Unblock failed. Cannot proceed.")
                return False, None, msgs

    # ── existing monitor on same phy ──
    existing_mon = _existing_monitor_on_phy(phy)
    if existing_mon:
        msgs.append(f"Monitor already exists: {existing_mon} on [{phy}]")
        if channel:
            ok, ch_msg = validate_and_set_channel(existing_mon, phy, channel)
            if ch_msg:
                msgs.append(ch_msg)
        return True, existing_mon, msgs

    # ── qcacld (icnss) ──
    if driver == "icnss":
        icnss_file = "/sys/module/wlan/parameters/con_mode"
        if not Path(icnss_file).exists():
            return False, None, msgs + [f"Cannot find {icnss_file}"]
        if not os.access(icnss_file, os.W_OK):
            return False, None, msgs + [f"{icnss_file} not writable"]
        run(["ip", "link", "set", iface_name, "down"])
        write_sysfs(icnss_file, "4")
        run(["ip", "link", "set", iface_name, "up"])
        msgs.append(f"qcacld monitor enabled on {iface_name}")
        if channel:
            ok, ch_msg = validate_and_set_channel(iface_name, phy, channel)
            if ch_msg:
                msgs.append(ch_msg)
        save_state({"base": iface_name, "monitor": iface_name,
                     "phy": phy, "mode": "qcacld", "driver": driver,
                     "created": int(time.time())})
        return True, iface_name, msgs

    # ── direct type conversion (no-vif drivers) ──
    if not _phy_supports_vif(phy, driver):
        run(["ip", "link", "set", iface_name, "down"])
        ok, _, err = run(["iw", "dev", iface_name, "set", "type", "monitor"])
        if not ok:
            return False, None, msgs + [f"Failed to set monitor: {err}"]
        run(["ip", "link", "set", iface_name, "up"])
        msgs.append(f"Monitor enabled on {iface_name} (direct conversion)")
        if channel:
            ok, ch_msg = validate_and_set_channel(iface_name, phy, channel)
            if ch_msg:
                msgs.append(ch_msg)
        save_state({"base": iface_name, "monitor": iface_name,
                     "phy": phy, "mode": "convert", "driver": driver,
                     "created": int(time.time())})
        return True, iface_name, msgs

    # ── vif creation (preferred) ──
    mon_name = iface_name + "mon"
    if len(mon_name) > 15:
        msgs.append(f"'{mon_name}' exceeds 15 chars, finding short name...")
        mon_name = _find_free_interface_name("mon")
        if not mon_name:
            return False, None, msgs + ["No free interface name available."]

    if Path(f"/sys/class/net/{mon_name}").exists():
        existing_type = read_sysfs(f"/sys/class/net/{mon_name}/type")
        if existing_type != "803":
            return False, None, msgs + [
                f"{mon_name} exists but is NOT monitor mode.",
                f"Run 'iw {mon_name} del' first.",
            ]

    run(["ip", "link", "set", iface_name, "down"])
    ok, _, err = run(["iw", "phy", phy, "interface", "add", mon_name, "type", "monitor"])

    if not ok:
        return False, None, msgs + [f"Failed to create monitor vif: {err}"]

    time.sleep(1)

    actual_name = _resolve_created_name(phy, "803")
    if actual_name:
        mon_name = actual_name
    else:
        msgs.append(f"{mon_name} created but not in monitor mode. Removing.")
        run(["iw", mon_name, "del"])
        return False, None, msgs

    actual_type = read_sysfs(f"/sys/class/net/{mon_name}/type")
    if actual_type != "803":
        msgs.append(f"{mon_name} type is {actual_type}, not 803. Removing.")
        run(["iw", mon_name, "del"])
        return False, None, msgs

    if channel:
        ok, ch_msg = validate_and_set_channel(mon_name, phy, channel)
        if ch_msg:
            msgs.append(ch_msg)
    else:
        run(["ip", "link", "set", mon_name, "up"])

    msgs.append(f"Monitor vif enabled: [{phy}]{mon_name}")

    if sysinfo.is_rpi_wireless:
        run(["iw", iface_name, "del"])
        msgs.append(f"Station vif [{phy}]{iface_name} removed (RPi onboard)")
    else:
        msgs.append(f"Station vif [{phy}]{iface_name} left down")

    save_state({"base": iface_name, "monitor": mon_name,
                 "phy": phy, "mode": "vif", "driver": driver,
                 "created": int(time.time())})
    return True, mon_name, msgs


def stop_monitor(iface_name, sysinfo=None):
    """Disable monitor mode. Returns (success, messages)."""
    if sysinfo is None:
        sysinfo = SystemInfo()

    msgs = []
    state = load_state(iface_name)

    if state is None:
        for f in STATE_DIR.glob("*.json"):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                if data.get("monitor") == iface_name or data.get("base") == iface_name:
                    state = data
                    break
            except Exception:
                pass

    if state is None:
        ifaces = discover_interfaces(sysinfo)
        wi = None
        for i in ifaces:
            if i.name == iface_name:
                wi = i
                break
        if wi is None:
            return False, [f"Interface {iface_name} not found."]
        if not wi.is_monitor:
            return False, [
                f"{iface_name} is not in monitor mode.",
                "Use 'iw <dev> del' manually if needed.",
            ]
        state = {
            "base": iface_name.replace("mon", ""),
            "monitor": iface_name,
            "phy": wi.phy,
            "mode": "vif" if iface_name.endswith("mon") else "convert",
            "driver": wi.driver,
        }

    mode = state.get("mode", "vif")
    base = state.get("base")
    monitor = state.get("monitor")
    phy = state.get("phy")

    # ── qcacld restore ──
    if mode == "qcacld":
        icnss_file = "/sys/module/wlan/parameters/con_mode"
        if Path(icnss_file).exists() and os.access(icnss_file, os.W_OK):
            write_sysfs(icnss_file, "0")
            run(["ip", "link", "set", base, "up"])
            msgs.append(f"qcacld managed mode restored on {base}")
        else:
            msgs.append(f"Cannot write to {icnss_file}")
        delete_state(monitor)
        return True, msgs

    # ── direct conversion restore ──
    if mode == "convert":
        run(["ip", "link", "set", base, "down"])
        ok, _, err = run(["iw", "dev", base, "set", "type", "managed"])
        if not ok:
            return False, msgs + [f"Failed to set managed: {err}"]
        run(["ip", "link", "set", base, "up"])
        msgs.append(f"Managed mode restored on {base}")
        delete_state(monitor)
        return True, msgs

    # ── vif removal ──
    need_station = True
    net_dir = Path(f"/sys/class/ieee80211/{phy}/device/net")
    if net_dir.is_dir():
        for entry in net_dir.iterdir():
            if read_sysfs(str(entry / "type")) == "1":
                need_station = False
                msgs.append(f"Station vif exists: {entry.name}")
                break

    if need_station:
        sta_name = base
        if Path(f"/sys/class/net/{sta_name}").exists():
            sta_phy = read_sysfs(f"/sys/class/net/{sta_name}/phy80211/name")
            if sta_phy != phy:
                sta_name = _find_free_interface_name("") or base

        ok, _, err = run(["iw", "phy", phy, "interface", "add", sta_name, "type", "station"])
        if ok:
            time.sleep(1)
            actual = _resolve_created_name(phy, "1")
            if actual:
                sta_name = actual
            msgs.append(f"Station vif created: [{phy}]{sta_name}")
        else:
            msgs.append(f"Warning: could not create station vif: {err}")

    run(["ip", "link", "set", monitor, "down"])
    ok, _, err = run(["iw", "dev", monitor, "del"])
    if not ok:
        remove_file = f"/sys/class/ieee80211/{phy}/remove_iface"
        if Path(remove_file).exists():
            write_sysfs(remove_file, monitor)
            msgs.append(f"Monitor vif {monitor} removed via sysfs")
        else:
            return False, msgs + [f"Failed to remove {monitor}: {err}"]
    else:
        msgs.append(f"Monitor vif [{phy}]{monitor} removed")

    delete_state(monitor)
    return True, msgs

# ═══════════════════════════════════════════════
#  STATE MANAGEMENT
# ═══════════════════════════════════════════════

def _ensure_state_dir():
    try:
        STATE_DIR.mkdir(exist_ok=True, parents=True)
    except PermissionError:
        pass


def state_file(iface):
    return STATE_DIR / f"{iface}.json"


def save_state(data):
    _ensure_state_dir()
    try:
        with open(state_file(data["monitor"]), "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load_state(iface):
    try:
        with open(state_file(iface)) as f:
            return json.load(f)
    except Exception:
        return None


def delete_state(iface):
    try:
        state_file(iface).unlink(missing_ok=True)
    except Exception:
        pass

# ═══════════════════════════════════════════════
#  WL (BROADCOM) SPECIAL HANDLING
# ═══════════════════════════════════════════════

def start_wl_monitor(iface):
    brcm = Path("/proc/brcm_monitor0")
    if not brcm.exists():
        return False, "This wl version does not support monitor mode."
    current = read_sysfs(str(brcm))
    if current == "1":
        return True, f"wl monitor already enabled for {iface}"
    if not os.access(str(brcm), os.W_OK):
        return False, "Cannot write to /proc/brcm_monitor0"
    if write_sysfs(str(brcm), "1"):
        return True, f"wl experimental monitor enabled for {iface} on prism0"
    return False, f"Failed to enable wl monitor for {iface}"


def stop_wl_monitor(iface):
    brcm = Path("/proc/brcm_monitor0")
    if not brcm.exists():
        return False, "This wl version does not support monitor mode."
    current = read_sysfs(str(brcm))
    if current == "0":
        return True, f"wl monitor already disabled for {iface}"
    if write_sysfs(str(brcm), "0"):
        return True, f"wl monitor disabled for {iface}"
    return False, f"Failed to disable wl monitor for {iface}"

# ═══════════════════════════════════════════════
#  CLI COMMANDS
# ═══════════════════════════════════════════════

def _dynamic_table(headers, rows, padding=2):
    """
    Build a dynamically-spaced table where each column expands
    to fit the widest entry across the header and all data rows.
    Returns list of formatted lines (header, separator, data rows).
    """
    ncols = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(cells):
        parts = []
        for i, cell in enumerate(cells):
            s = str(cell)
            if i < ncols - 1:
                parts.append(s.ljust(widths[i] + padding))
            else:
                parts.append(s)
        return "".join(parts)

    output = []
    output.append(fmt_row(headers))
    total_w = sum(w + padding for w in widths[:-1]) + widths[-1]
    output.append("\u2500" * total_w)
    for row in rows:
        output.append(fmt_row(row))
    return output


def cmd_list(verbose=False):
    sysinfo = SystemInfo()
    for w in sysinfo.check_kernel_breakage():
        print(w)

    lost = discover_lost_phys()
    for phy in lost:
        print(f"  Found {phy} with no interfaces \u2014 "
              f"'iw phy {phy} interface add <n> type station' to recover")

    ifaces = discover_interfaces(sysinfo)

    if not ifaces:
        print("\nNo wireless interfaces found.")
        return

    if verbose:
        print(f"\nKernel: {sysinfo.kernel_version}")
        if sysinfo.vm_type:
            print(f"VM: {sysinfo.vm_type} (detected via {sysinfo.vm_source})")
            print("  VT-d passthrough needed for PCI devices; USB works without it.")

        ok, out, _ = run(["iw", "reg", "get"])
        if ok:
            if "country 00:" in out:
                print("Regulatory domain: UNSET \u2014 consider 'iw reg set XX'")
            else:
                for m in re.finditer(r"country\s+(\w+):", out):
                    print(f"Regulatory domain: {m.group(1)}")

        print()
        headers = ["Src", "PHY", "Interface", "Driver", "Stack",
                    "Firmware", "Chipset", "Info"]
        rows = []
        for wi in ifaces:
            rows.append([
                f" {wi.from_source}",
                wi.phy or "\u2014",
                wi.name,
                wi.driver,
                wi.stack or "\u2014",
                wi.firmware or "\u2014",
                wi.chipset or "\u2014",
                wi.extended or "",
            ])

        for line in _dynamic_table(headers, rows):
            print(line)

        print()
        print("  K=kernel  C=compat-wireless  V=vendor  S=staging  ?=unknown")
    else:
        print()
        headers = ["PHY", "Interface", "Driver", "Mode", "Chipset"]
        rows = []
        for wi in ifaces:
            rows.append([
                wi.phy or "\u2014",
                wi.name,
                wi.driver,
                wi.mode_str,
                wi.chipset or "\u2014",
            ])

        for line in _dynamic_table(headers, rows):
            print(line)

    print()



def cmd_check(iface=None, kill=False, kill_all=False):
    sysinfo = SystemInfo()
    for w in sysinfo.check_kernel_breakage():
        print(w)

    if kill_all:
        print("\n  Stopping ALL interfering services and processes (global)...\n")
        stopped = stop_all_services()
        if stopped:
            for s in stopped:
                print(f"    ✗ {s}")
        else:
            print("    Nothing to stop.")
        print()
        return

    if kill and iface:
        print(f"\n  Stopping services/processes bound to {iface}...\n")
        stopped = stop_services_for_interface(iface)
        if stopped:
            for s in stopped:
                print(f"    ✗ {s}")
        else:
            print("    No interface-specific processes found.")

        remaining = find_interfering_processes()
        if remaining:
            print(f"\n  Left running (not bound to {iface}):")
            for proc in remaining:
                bound_str = ", ".join(proc["interfaces"]) if proc["interfaces"] else "?"
                print(f"    PID {proc['pid']:<6}  {proc['name']:<20}  ({bound_str})")
        print()
        return

    if iface:
        targeted, untargeted = find_processes_for_interface(iface)

        print(f"\n  Processes that may interfere with {iface}:\n")
        if targeted:
            for proc in targeted:
                flag = " [ambiguous]" if proc.get("ambiguous") else ""
                print(f"    PID {proc['pid']:<6}  {proc['name']:<20}  "
                      f"{proc['cmdline'][:60]}{flag}")
        else:
            print("    None found.")

        if untargeted:
            print(f"\n  Other interfering processes (different interfaces):")
            for proc in untargeted:
                bound = ", ".join(proc["interfaces"]) if proc["interfaces"] else "?"
                print(f"    PID {proc['pid']:<6}  {proc['name']:<20}  bound to: {bound}")
    else:
        procs = find_interfering_processes()
        print("\n  Interfering processes:\n")
        if procs:
            for proc in procs:
                bound = ", ".join(proc["interfaces"]) if proc["interfaces"] else "?"
                print(f"    PID {proc['pid']:<6}  {proc['name']:<20}  bound to: {bound}")
            print()
            print("  Use 'airmon-nx check --kill <iface>' to kill per-interface.")
            print("  Use 'airmon-nx check --kill-all' for global kill (destructive).")
        else:
            print("    None found.")

    print()


def cmd_start(iface, channel=None):
    sysinfo = SystemInfo()
    for w in sysinfo.check_kernel_breakage():
        print(w)

    if not Path(f"/sys/class/net/{iface}").exists():
        print(f"\n  Interface '{iface}' does not exist.")
        print(f"  Run 'airmon-nx list' to see available interfaces.\n")
        return

    ifaces = discover_interfaces(sysinfo)
    wi = None
    for i in ifaces:
        if i.name == iface:
            wi = i
            break

    if wi and wi.driver == "wl":
        ok, msg = start_wl_monitor(iface)
        print(f"\n  {msg}\n")
        return

    procs = find_interfering_processes()
    relevant = [p for p in procs if iface in p["interfaces"] or not p["interfaces"]]
    if relevant:
        print(f"\n  WARNING: {len(relevant)} potentially interfering process(es).")
        print(f"  Run 'airmon-nx check --kill {iface}' to stop them safely.\n")

    print()
    ok, mon_name, msgs = start_monitor(iface, channel, sysinfo)

    for m in msgs:
        for line in m.split("\n"):
            print(f"  {line}")

    if ok:
        print(f"\n  ✓ Monitor mode active: {mon_name}\n")
    else:
        print(f"\n  ✗ Failed to enable monitor mode.\n")


def cmd_stop(iface):
    sysinfo = SystemInfo()

    if not Path(f"/sys/class/net/{iface}").exists():
        state = load_state(iface)
        if state is None:
            print(f"\n  Interface '{iface}' not found and no state file.\n")
            return

    ifaces = discover_interfaces(sysinfo)
    wi = None
    for i in ifaces:
        if i.name == iface:
            wi = i
            break

    if wi and wi.driver == "wl":
        ok, msg = stop_wl_monitor(iface)
        print(f"\n  {msg}\n")
        return

    print()
    ok, msgs = stop_monitor(iface, sysinfo)

    for m in msgs:
        for line in m.split("\n"):
            print(f"  {line}")

    if ok:
        print(f"\n  ✓ Monitor mode disabled.\n")
    else:
        print(f"\n  ✗ Failed to disable monitor mode.\n")

# ═══════════════════════════════════════════════
#  NCURSES TUI
# ═══════════════════════════════════════════════

class TUI:
    """Rich ncurses interface for airmon-nx."""

    # color pairs
    C_HEADER = 1
    C_NORMAL = 2
    C_HIGHLIGHT = 3
    C_MONITOR = 4
    C_MANAGED = 5
    C_WARNING = 6
    C_SUCCESS = 7
    C_DIM = 8
    C_BAR = 9
    C_SELECTED = 10
    C_BORDER = 11

    def __init__(self, stdscr):
        self.scr = stdscr
        self.sysinfo = SystemInfo()
        self.ifaces = []
        self.procs = []
        self.selected = 0
        self.scroll = 0
        self.mode = "main"
        self.detail_iface = None
        self.detail_scroll = 0
        self.toast = None
        self.toast_time = 0
        self.toast_err = False
        self.last_refresh = 0
        self.refresh_interval = 3

    def init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        pairs = [
            (self.C_HEADER,    curses.COLOR_BLACK,   curses.COLOR_CYAN),
            (self.C_NORMAL,    -1, -1),
            (self.C_HIGHLIGHT, curses.COLOR_CYAN,    -1),
            (self.C_MONITOR,   curses.COLOR_GREEN,   -1),
            (self.C_MANAGED,   curses.COLOR_YELLOW,  -1),
            (self.C_WARNING,   curses.COLOR_RED,     -1),
            (self.C_SUCCESS,   curses.COLOR_GREEN,   -1),
            (self.C_DIM,       curses.COLOR_WHITE,   -1),
            (self.C_BAR,       curses.COLOR_BLACK,   curses.COLOR_WHITE),
            (self.C_SELECTED,  curses.COLOR_BLACK,   curses.COLOR_CYAN),
            (self.C_BORDER,    curses.COLOR_CYAN,    -1),
        ]
        for pid, fg, bg in pairs:
            try:
                curses.init_pair(pid, fg, bg)
            except curses.error:
                pass

    def cp(self, pair_id):
        return curses.color_pair(pair_id)

    def refresh_data(self):
        self.ifaces = discover_interfaces(self.sysinfo)
        self.procs = find_interfering_processes()
        self.last_refresh = time.time()

    def toast_msg(self, text, err=False):
        self.toast = text
        self.toast_err = err
        self.toast_time = time.time()

    def run(self):
        self.init_colors()
        curses.curs_set(0)
        self.scr.timeout(500)
        self.refresh_data()

        while True:
            self.draw()
            key = self.scr.getch()
            if key == -1:
                if time.time() - self.last_refresh > self.refresh_interval:
                    self.refresh_data()
                continue

            handlers = {
                "main": self._input_main,
                "detail": self._input_detail,
                "confirm_kill": self._input_confirm_kill,
                "confirm_kill_all": self._input_confirm_kill_all,
                "help": self._input_help,
            }
            handler = handlers.get(self.mode, self._input_main)
            handler(key)

    # ── safe drawing ──

    def _put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        max_len = w - x - 1
        if max_len <= 0:
            return
        try:
            self.scr.addnstr(y, x, text, max_len, attr)
        except curses.error:
            pass

    def _hline(self, y, x, ch, length, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h:
            return
        length = min(length, w - x - 1)
        if length <= 0:
            return
        try:
            self.scr.hline(y, x, ch, length, attr)
        except curses.error:
            pass

    def _fill_line(self, y, attr):
        """Fill an entire line with a given attribute (for bars/headers)."""
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h:
            return
        self._put(y, 0, " " * (w - 1), attr)

    # ── header / footer ──

    def _draw_header_bar(self, title="airmon-nx"):
        h, w = self.scr.getmaxyx()
        self._fill_line(0, self.cp(self.C_HEADER) | curses.A_BOLD)
        text = f" {title} v{VERSION}"
        self._put(0, 0, text, self.cp(self.C_HEADER) | curses.A_BOLD)

        # right-aligned info
        kinfo = f"kernel {self.sysinfo.kernel_version} "
        self._put(0, max(0, w - len(kinfo) - 1), kinfo,
                  self.cp(self.C_HEADER))

    def _draw_footer(self, keys_text):
        h, w = self.scr.getmaxyx()
        self._fill_line(h - 1, self.cp(self.C_BAR))
        self._put(h - 1, 0, keys_text[:w - 1], self.cp(self.C_BAR))

    def _draw_toast(self):
        if not self.toast or time.time() - self.toast_time > 5:
            return
        h, w = self.scr.getmaxyx()
        color = self.cp(self.C_WARNING if self.toast_err else self.C_SUCCESS) | curses.A_BOLD
        self._put(h - 2, 2, self.toast[:w - 4], color)

    # ── drawing routines ──

    def draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        if h < 8 or w < 40:
            self._put(0, 0, "Terminal too small")
            self.scr.refresh()
            return

        drawers = {
            "main": self._draw_main,
            "detail": self._draw_detail,
            "confirm_kill": self._draw_confirm_kill,
            "confirm_kill_all": self._draw_confirm_kill_all,
            "help": self._draw_help,
        }
        drawers.get(self.mode, self._draw_main)(h, w)
        self._draw_toast()
        self.scr.refresh()

    def _draw_main(self, h, w):
        self._draw_header_bar()
        row = 2

        # ── section: interfaces ──
        self._put(row, 2, "╶ Interfaces ╴",
                  self.cp(self.C_BORDER) | curses.A_BOLD)
        row += 1

        # column headers
        hdr = f"  {'PHY':>7}  {'Name':<14}  {'Driver':<13}  {'Mode':<10}  {'Chipset'}"
        self._put(row, 1, hdr[:w - 2], self.cp(self.C_DIM) | curses.A_BOLD)
        row += 1
        self._hline(row, 2, curses.ACS_HLINE, min(w - 4, 90), self.cp(self.C_DIM))
        row += 1

        if not self.ifaces:
            self._put(row, 4, "No wireless interfaces detected",
                      self.cp(self.C_WARNING))
            row += 2
        else:
            # compute available rows for table
            # reserve: 1 header + 1 underline + processes section (~6) + footer
            proc_rows = min(len(self.procs) + 3, 8)
            table_h = max(2, h - row - proc_rows - 3)

            if self.selected < self.scroll:
                self.scroll = self.selected
            if self.selected >= self.scroll + table_h:
                self.scroll = self.selected - table_h + 1

            for idx in range(self.scroll, min(len(self.ifaces), self.scroll + table_h)):
                wi = self.ifaces[idx]
                is_sel = (idx == self.selected)

                # mode indicator
                if wi.is_monitor:
                    mode_sym = "● "
                    mode_color = self.C_MONITOR
                elif wi.connected:
                    mode_sym = "◌ "
                    mode_color = self.C_MANAGED
                else:
                    mode_sym = "  "
                    mode_color = self.C_NORMAL

                line_text = (
                    f"  {wi.phy or '—':>7}  {wi.name:<14}  {wi.driver:<13}  "
                    f"{mode_sym}{wi.mode_str:<8}  "
                    f"{(wi.chipset or '—')[:max(1, w - 58)]}"
                )

                if is_sel:
                    self._fill_line(row, self.cp(self.C_SELECTED))
                    self._put(row, 1, "▸", self.cp(self.C_SELECTED) | curses.A_BOLD)
                    self._put(row, 2, line_text[:w - 3],
                              self.cp(self.C_SELECTED) | curses.A_BOLD)
                else:
                    self._put(row, 2, line_text[:w - 3], self.cp(mode_color))

                row += 1

            # scroll indicators
            if self.scroll > 0:
                self._put(row - table_h, w - 3, "▲", self.cp(self.C_DIM))
            if self.scroll + table_h < len(self.ifaces):
                self._put(row - 1, w - 3, "▼", self.cp(self.C_DIM))

            row += 1

        # ── section: processes ──
        self._put(row, 2, "╶ Interfering Processes ╴",
                  self.cp(self.C_BORDER) | curses.A_BOLD)
        row += 1
        self._hline(row, 2, curses.ACS_HLINE, min(w - 4, 90), self.cp(self.C_DIM))
        row += 1

        max_proc_rows = max(1, h - row - 3)
        if not self.procs:
            self._put(row, 4, "✓ None detected", self.cp(self.C_SUCCESS))
        else:
            for i, proc in enumerate(self.procs[:max_proc_rows]):
                bound = ", ".join(proc["interfaces"]) if proc["interfaces"] else "?"
                pline = f"  {proc['pid']:<6}  {proc['name']:<18}  → {bound}"
                self._put(row, 3, pline[:w - 5], self.cp(self.C_WARNING))
                row += 1

        self._draw_footer(
            " ↑↓/jk Navigate │ ⏎ Details │ m Monitor │ "
            "K Kill-all │ r Refresh │ ? Help │ q Quit "
        )

    def _draw_detail(self, h, w):
        wi = self.detail_iface
        if not wi:
            self.mode = "main"
            return

        self._draw_header_bar(f"Interface: {wi.name}")

        row = 2
        fields = [
            ("Interface",  wi.name),
            ("PHY",        wi.phy or "—"),
            ("Driver",     f"{wi.driver}" + (f" (raw: {wi.driver_raw})" if wi.driver_raw != wi.driver else "")),
            ("Stack",      wi.stack or "—"),
            ("Bus",        wi.bus or "—"),
            ("Mode",       wi.mode_str),
            ("Connected",  "yes" if wi.connected else "no"),
            ("Chipset",    wi.chipset or "—"),
            ("Firmware",   wi.firmware or "—"),
            ("Source",     f"{wi.from_source} ({'kernel' if wi.from_source == 'K' else 'compat' if wi.from_source == 'C' else 'vendor' if wi.from_source == 'V' else 'staging' if wi.from_source == 'S' else '?'})"),
            ("Device ID",  wi.device_id or "—"),
            ("Extended",   wi.extended or "—"),
        ]

        # scrollable field list
        visible = max(1, h - 8)  # room for header, process section, footer
        max_scroll = max(0, len(fields) - visible)
        self.detail_scroll = max(0, min(self.detail_scroll, max_scroll))
        start = self.detail_scroll
        end = start + visible

        for i, (label, value) in enumerate(fields[start:end], start=start):
            if row >= h - 6:
                break
            self._put(row, 3, f"{label + ':':<14}",
                      self.cp(self.C_DIM) | curses.A_BOLD)
            val_color = self.C_MONITOR if (label == "Mode" and wi.is_monitor) else self.C_NORMAL
            self._put(row, 18, str(value)[:max(1, w - 20)], self.cp(val_color))
            row += 1

        row += 1

        # processes bound to this interface
        self._put(row, 3, f"Processes using {wi.name}:",
                  self.cp(self.C_DIM) | curses.A_BOLD)
        row += 1
        targeted, _ = find_processes_for_interface(wi.name)
        if targeted:
            for proc in targeted[:max(1, h - row - 3)]:
                amb = " [?]" if proc.get("ambiguous") else ""
                self._put(row, 5,
                          f"PID {proc['pid']:<6}  {proc['name']}{amb}",
                          self.cp(self.C_WARNING))
                row += 1
        else:
            self._put(row, 5, "None", self.cp(self.C_SUCCESS))

        action = "Stop monitor" if wi.is_monitor else "Start monitor"
        self._draw_footer(
            f" b/\u2190/Esc Back \u2502 \u2191\u2193 Scroll \u2502 m {action} \u2502 k Kill bound \u2502 r Refresh "
        )

    def _draw_dialog(self, h, w, title, body_lines):
        """Draw a centered dialog box."""
        box_w = min(w - 6, max(len(title) + 8, 50))
        box_h = len(body_lines) + 4
        bx = max(1, (w - box_w) // 2)
        by = max(1, (h - box_h) // 2)

        # border
        for dy in range(box_h):
            self._fill_line(by + dy, self.cp(self.C_BAR))

        self._put(by, bx + 1, f"┌{'─' * (box_w - 2)}┐", self.cp(self.C_BAR))
        for dy in range(1, box_h - 1):
            self._put(by + dy, bx + 1, "│", self.cp(self.C_BAR))
            self._put(by + dy, bx + box_w - 2, "│", self.cp(self.C_BAR))
        self._put(by + box_h - 1, bx + 1, f"└{'─' * (box_w - 2)}┘", self.cp(self.C_BAR))

        # title
        self._put(by + 1, bx + 3, title[:box_w - 6],
                  self.cp(self.C_BAR) | curses.A_BOLD)

        # body
        for i, line in enumerate(body_lines):
            self._put(by + 3 + i, bx + 3, line[:box_w - 6], self.cp(self.C_BAR))

    def _draw_confirm_kill(self, h, w):
        self._draw_detail(h, w)
        name = self.detail_iface.name if self.detail_iface else "?"
        self._draw_dialog(h, w,
                          f"Kill processes bound to {name}?",
                          ["This will SIGKILL processes using only this interface.",
                           "Other interfaces will not be affected.",
                           "",
                           "Press y to confirm, any other key to cancel."])

    def _draw_confirm_kill_all(self, h, w):
        self._draw_main(h, w)
        self._draw_dialog(h, w,
                          "GLOBAL KILL — Stop ALL interfering processes?",
                          ["This will stop system services (NetworkManager, etc.)",
                           "and SIGKILL all interfering processes system-wide.",
                           "ALL wireless interfaces will be affected.",
                           "",
                           "Press y to confirm, any other key to cancel."])

    def _draw_help(self, h, w):
        self._draw_header_bar("Help")

        sections = [
            ("Navigation", [
                "↑/k  ↓/j      Move selection",
                "Enter          View interface details",
                "b / ← / Esc    Go back",
            ]),
            ("Actions", [
                "m              Toggle monitor mode on selected interface",
                "k              Kill processes bound to interface (detail view)",
                "K              Kill ALL interfering processes (global, destructive)",
                "r              Refresh data",
            ]),
            ("Kill Modes", [
                "Targeted (k):  Only kills processes using the selected interface.",
                "               Safe for multi-adapter setups.",
                "Global   (K):  Kills everything — matches original airmon-ng behavior.",
                "               Use when you want a clean slate.",
            ]),
            ("General", [
                "?/h            This help screen",
                "q              Quit",
            ]),
        ]

        row = 3
        for title, lines in sections:
            if row >= h - 3:
                break
            self._put(row, 3, title,
                      self.cp(self.C_HIGHLIGHT) | curses.A_BOLD)
            row += 1
            for line in lines:
                if row >= h - 3:
                    break
                self._put(row, 5, line, self.cp(self.C_NORMAL))
                row += 1
            row += 1

        self._draw_footer(" Press any key to return ")

    # ── input handlers ──

    def _input_main(self, key):
        if key in (ord('q'), ord('Q'), 27):
            raise SystemExit(0)
        elif key == ord('r'):
            self.refresh_data()
            self.toast_msg("Refreshed")
        elif key in (ord('?'), ord('h')):
            self.mode = "help"
        elif key in (curses.KEY_UP, ord('k')):
            self.selected = max(0, self.selected - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            self.selected = min(len(self.ifaces) - 1, self.selected + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            if self.ifaces:
                self.detail_iface = self.ifaces[self.selected]
                self.detail_scroll = 0
                self.mode = "detail"
        elif key == ord('m'):
            if self.ifaces:
                wi = self.ifaces[self.selected]
                self._action_toggle(wi)
        elif key == ord('K'):
            if self.procs:
                self.mode = "confirm_kill_all"

    def _input_detail(self, key):
        if key in (ord('q'), 27, ord('b'), curses.KEY_LEFT):
            self.mode = "main"
            self.detail_iface = None
        elif key == curses.KEY_UP:
            self.detail_scroll = max(0, self.detail_scroll - 1)
        elif key == curses.KEY_DOWN:
            self.detail_scroll += 1
        elif key == ord('m'):
            if self.detail_iface:
                self._action_toggle(self.detail_iface)
                self.mode = "main"
        elif key == ord('k'):
            if self.detail_iface:
                self.mode = "confirm_kill"
        elif key == ord('r'):
            self.refresh_data()
            if self.detail_iface:
                for i in self.ifaces:
                    if i.name == self.detail_iface.name:
                        self.detail_iface = i
                        break

    def _input_confirm_kill(self, key):
        if key == ord('y'):
            if self.detail_iface:
                stopped = stop_services_for_interface(self.detail_iface.name)
                self.toast_msg(
                    f"Stopped {len(stopped)} process(es) for {self.detail_iface.name}"
                )
                self.refresh_data()
        self.mode = "detail"

    def _input_confirm_kill_all(self, key):
        if key == ord('y'):
            stopped = stop_all_services()
            self.toast_msg(f"Global kill: stopped {len(stopped)} item(s)")
            self.refresh_data()
        self.mode = "main"

    def _input_help(self, key):
        self.mode = "main"

    # ── actions ──

    def _action_toggle(self, wi):
        if wi.is_monitor:
            ok, msgs = stop_monitor(wi.name, sysinfo=self.sysinfo)
            self.toast_msg(
                "Monitor disabled" if ok else f"Failed: {msgs[-1] if msgs else '?'}",
                err=not ok,
            )
        else:
            ok, mon, msgs = start_monitor(wi.name, sysinfo=self.sysinfo)
            self.toast_msg(
                f"Monitor enabled: {mon}" if ok else f"Failed: {msgs[-1] if msgs else '?'}",
                err=not ok,
            )
        self.refresh_data()


def cmd_ui():
    def _run(stdscr):
        TUI(stdscr).run()
    try:
        curses.wrapper(_run)
    except KeyboardInterrupt:
        pass

# ═══════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════

def preflight():
    if not Path("/sys").is_dir():
        eprint("ERROR: /sys does not exist. CONFIG_SYSFS is required.")
        sys.exit(1)

    if tool_exists("mountpoint"):
        rc = run_rc(["mountpoint", "-q", "/sys"])
        if rc != 0:
            eprint("/sys is not mounted. Try: mount -t sysfs sysfs /sys")
            sys.exit(1)

    if not is_root():
        eprint("ERROR: airmon-nx must be run as root.")
        sys.exit(1)

    missing = [t for t in REQUIRED_TOOLS if not tool_exists(t)]
    if missing:
        eprint(f"ERROR: required tools missing: {', '.join(missing)}")
        eprint("Install them from your distribution's package manager.")
        sys.exit(1)

    for t in RECOMMENDED_TOOLS:
        if not tool_exists(t):
            eprint(f"NOTE: {t} not found — some features may be limited.")

    _ensure_state_dir()


def main():
    preflight()

    parser = argparse.ArgumentParser(
        prog="airmon-nx",
        description=f"airmon-nx v{VERSION} — modern wireless monitor mode manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              airmon-nx list                       Show all wireless interfaces
              airmon-nx list -v                     Verbose listing with full details
              airmon-nx check wlan0                 Show processes that may interfere
              airmon-nx check --kill wlan0          Kill only processes using wlan0
              airmon-nx check --kill-all            Kill ALL interfering processes
              airmon-nx start wlan0                 Enable monitor mode
              airmon-nx start wlan0 6               Monitor mode on channel 6
              airmon-nx start wlan0 5180            Monitor mode on 5180 MHz
              airmon-nx stop wlan0mon               Disable monitor mode
              airmon-nx ui                          Interactive ncurses interface
        """),
    )

    sub = parser.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="List wireless interfaces")
    p_list.add_argument("-v", "--verbose", action="store_true",
                        help="Show extended details")

    p_check = sub.add_parser("check", help="Check/kill interfering processes")
    p_check.add_argument("iface", nargs="?", default=None,
                         help="Interface to check")
    kill_grp = p_check.add_mutually_exclusive_group()
    kill_grp.add_argument("--kill", action="store_true",
                          help="Kill processes bound to specified interface")
    kill_grp.add_argument("--kill-all", action="store_true",
                          help="Kill ALL interfering processes (global)")

    p_start = sub.add_parser("start", help="Enable monitor mode")
    p_start.add_argument("iface", help="Interface name")
    p_start.add_argument("channel", nargs="?", default=None,
                         help="Channel or frequency (MHz)")

    p_stop = sub.add_parser("stop", help="Disable monitor mode")
    p_stop.add_argument("iface", help="Monitor interface to stop")

    sub.add_parser("ui", help="Interactive ncurses interface")

    args = parser.parse_args()

    try:
        if args.cmd == "list":
            cmd_list(verbose=args.verbose)
        elif args.cmd == "check":
            if args.kill and not args.iface:
                eprint("ERROR: --kill requires an interface name.")
                eprint("  Use --kill-all for global kill.")
                sys.exit(1)
            cmd_check(iface=args.iface, kill=args.kill, kill_all=args.kill_all)
        elif args.cmd == "start":
            cmd_start(args.iface, channel=args.channel)
        elif args.cmd == "stop":
            cmd_stop(args.iface)
        elif args.cmd == "ui":
            cmd_ui()
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()