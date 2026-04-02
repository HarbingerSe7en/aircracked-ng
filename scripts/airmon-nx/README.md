# airmon-nx

A modern, robust replacement for `airmon-ng` — rewritten from scratch in Python.

**airmon-nx** provides full feature parity with the original `airmon-ng` shell script while introducing targeted process management, persistent state tracking, driver-aware mode switching, and an interactive ncurses interface. It uses only the Python standard library — no virtual environment, no `pip install`, no external dependencies.

---

## Why airmon-nx?

The original `airmon-ng` is a ~1200-line shell script that has accumulated years of quirks, hardcoded tab formatting, and a destructive approach to process management (`check kill` wipes *every* interfering process system-wide, even those bound to other interfaces). It works, but it's brittle and hard to extend.

**airmon-nx** addresses this with:

- **Targeted process killing** — stop only the processes using the specific interface you're working with, leaving other adapters untouched. The global kill-all is still available when you want a clean slate.
- **Persistent state** — monitor sessions are tracked in `/run/airmon-nx/*.json`, so `stop` can reliably restore the correct interface state even if the original interface was renamed by udev.
- **Driver-aware mode switching** — known-broken drivers (Realtek 88XXau, Qualcomm qcacld/icnss, etc.) are detected upfront and routed to the correct codepath instead of failing and falling through.
- **Dynamic output formatting** — column widths adapt to your actual data instead of breaking when an interface name or firmware string is longer than expected.
- **A real TUI** — live-updating ncurses interface with keyboard navigation, per-interface detail views, and inline monitor mode toggling.

---

## Requirements

**Python 3.6+** (stdlib only — no external packages)

**Required system tools:**

| Tool | Package | Purpose |
|------|---------|---------|
| `iw` | `iw` | Wireless configuration |
| `ip` | `iproute2` | Link management |

**Recommended (enables full functionality):**

| Tool | Package | Purpose |
|------|---------|---------|
| `ethtool` | `ethtool` | Driver/firmware detection |
| `lsusb` | `usbutils` | USB chipset identification |
| `lspci` | `pciutils` | PCI chipset identification |
| `rfkill` | `rfkill` or `util-linux` | Soft/hard block management |
| `modinfo` | `kmod` | Driver source detection |
| `nmcli` | `network-manager` | Targeted NM device control |

Install everything on Debian/Ubuntu:

```bash
sudo apt install iw iproute2 ethtool usbutils pciutils rfkill kmod
```

On Arch:

```bash
sudo pacman -S iw iproute2 ethtool usbutils pciutils util-linux kmod
```

---

## Installation

It's a single file. Copy it wherever you want:

```bash
sudo cp airmon-nx.py /usr/local/sbin/airmon-nx
sudo chmod +x /usr/local/sbin/airmon-nx
```

Or just run it directly:

```bash
sudo python3 airmon-nx.py <command>
```

---

## Usage

### List interfaces

```bash
# Basic listing
sudo airmon-nx list

# Example output:
# PHY    Interface        Driver          Mode       Chipset
# ──────────────────────────────────────────────────────────────────────────
# phy0   wlan0            iwlwifi         managed    Intel Corporation Wi-Fi 6 AX210/AX211/AX
# phy1   wlan1            mt7921u         managed    MediaTek Inc. Wireless_Device

# Verbose — includes driver source, stack, firmware, extended info
sudo airmon-nx list -v
```

The verbose view also shows kernel version, VM detection status, and regulatory domain.

### Enable monitor mode

```bash
# Default (auto-selects channel)
sudo airmon-nx start wlan0

# On a specific channel
sudo airmon-nx start wlan0 6

# On a specific frequency (MHz)
sudo airmon-nx start wlan0 5180
```

The tool will:
1. Check rfkill and attempt automatic unblock if needed
2. Detect the driver and choose the correct method (virtual interface, direct conversion, or qcacld path)
3. Validate the channel/frequency against hardware capabilities
4. Create the monitor interface and report the result

The monitor interface is typically named `wlan0mon`. If the name would exceed Linux's 15-character limit, a shorter name is assigned automatically.

### Disable monitor mode

```bash
sudo airmon-nx stop wlan0mon
```

This restores the station interface using the state saved during `start`. If no state file exists, it will attempt to reconstruct the correct restore path from sysfs.

### Check for interfering processes

```bash
# Show all interfering processes with interface binding info
sudo airmon-nx check

# Show only processes relevant to a specific interface
sudo airmon-nx check wlan0
```

Output separates processes into those bound to your target interface vs. those on other interfaces, so you can make an informed decision before killing anything.

### Kill interfering processes

```bash
# Targeted: kill only processes using wlan0
sudo airmon-nx check --kill wlan0

# Global: kill ALL interfering processes (matches original airmon-ng behavior)
sudo airmon-nx check --kill-all
```

**Targeted kill (`--kill <iface>`):**
- Tells NetworkManager to unmanage only the specified device (`nmcli device set <iface> managed no`)
- Kills only `wpa_supplicant`, `dhclient`, etc. instances that are bound to that interface
- Leaves processes on other interfaces running
- Reports what was left untouched

**Global kill (`--kill-all`):**
- Stops system services: NetworkManager, avahi-daemon, wicd, iwd
- SIGKILLs all remaining interfering processes system-wide
- This is the equivalent of the original `airmon-ng check kill`

### Interactive TUI

```bash
sudo airmon-nx ui
```

Launches a ncurses interface with:

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate interface list |
| `Enter` | View interface details |
| `m` | Toggle monitor mode on selected interface |
| `k` | Kill processes bound to interface (detail view) |
| `K` | Kill ALL interfering processes (global) |
| `r` | Refresh data |
| `b` / `←` / `Esc` | Go back |
| `?` / `h` | Help |
| `q` | Quit |

The TUI auto-refreshes every 3 seconds and shows both the interface table (color-coded by mode) and a live list of interfering processes with their interface bindings.

---

## How it works

### Monitor mode strategies

airmon-nx uses three different strategies depending on the driver:

**1. Virtual interface (vif)** — the preferred method for mac80211 drivers. Creates a separate `wlan0mon` interface in monitor mode alongside the base interface. Most modern drivers support this.

**2. Direct type conversion** — for drivers that don't support virtual interfaces (Realtek 88XXau, and any driver where `iw` reports "interface combinations are not supported"). Converts the existing interface in-place.

**3. qcacld control** — for Qualcomm's `icnss` driver. Writes to `/sys/module/wlan/parameters/con_mode` to switch modes.

The strategy is selected automatically based on driver detection and `iw phy info` output.

### State management

Each monitor session writes a JSON state file to `/run/airmon-nx/`:

```json
{
  "base": "wlan0",
  "monitor": "wlan0mon",
  "phy": "phy0",
  "mode": "vif",
  "driver": "iwlwifi",
  "created": 1711234567
}
```

This allows `stop` to reliably restore the correct interface state regardless of udev renames or manual intervention.

### Process-to-interface binding

When identifying which processes to kill, airmon-nx uses multiple heuristics:

1. **Command-line parsing** — scans `/proc/<pid>/cmdline` for `-i <iface>`, `--interface <iface>`, and bare interface name arguments
2. **NetworkManager query** — uses `nmcli -t -f DEVICE,TYPE,STATE device` to determine which WiFi devices NM is actively managing
3. **Ambiguity handling** — processes whose interface binding cannot be determined are flagged as `[ambiguous]` and included in targeted kill as a safety measure

### Driver detection

The driver detection pipeline mirrors the original `airmon-ng` with all its quirks:

1. Read `DRIVER=` from `/sys/class/net/<iface>/device/uevent`
2. If driver is `usb`, resolve through the USB sub-device uevent
3. Normalize vendor driver names through an alias table (e.g., `rtl88xxau` → `88XXau`)
4. Validate the driver module exists via `modinfo`
5. Fall back to `lspci -k` module detection for PCI devices

### Chipset identification

- **USB**: Parse modalias for VID:PID, cross-reference with `lsusb`
- **PCI/PCIe**: Read vendor/device from sysfs, cross-reference with `lspci`
- **SDIO**: Look up against a built-in table of known Broadcom SDIO device IDs
- **bcma**: Detected via ethtool bus-info

---

## Supported hardware quirks

| Driver | Quirk | Handling |
|--------|-------|----------|
| Realtek `88XXau` / `8812au` / `8814au` | No vif support | Direct type conversion |
| Qualcomm `icnss` (qcacld) | Proprietary mode control | `/sys/module/wlan/parameters/con_mode` |
| Broadcom `wl` | Limited monitor via procfs | `/proc/brcm_monitor0` |
| Broadcom `brcmsmac` | No injection | Noted in extended info |
| Realtek `r8712u` | No monitor at all | Noted in extended info |
| `rt2870sta` / `rt3070sta` / `rt5390sta` | Vendor drivers with kernel replacements | Recommends blacklisting and using kernel driver |
| `ar9170usb` / `arusb_lnx` | Deprecated, replaced by `carl9170` | Recommends replacement |
| Raspberry Pi onboard | Station vif should be removed | Auto-detected via `/proc/cpuinfo` revision |

---

## Comparison with airmon-ng

| Feature | airmon-ng | airmon-nx |
|---------|-----------|-----------|
| Language | POSIX shell | Python 3 (stdlib) |
| Process killing | Global only | Targeted per-interface + global |
| State tracking | None | JSON in `/run/airmon-nx/` |
| Column formatting | Hardcoded tabs | Dynamic widths |
| Interactive UI | None | ncurses TUI |
| rfkill handling | ✓ | ✓ + auto-unblock |
| VM detection | ✓ | ✓ (same detection chain) |
| Driver quirks | ✓ | ✓ (all ported) |
| Channel validation | ✓ | ✓ (with hardware capability check) |
| Chipset detection | ✓ | ✓ (USB/PCI/SDIO/bcma) |
| Lost phy recovery | ✓ (interactive) | ✓ (shows recovery command) |
| Kernel breakage warnings | ✓ (5.15) | ✓ |
| Dependencies | iw, ip, ethtool, lsusb, lspci, awk, grep | iw, ip (others optional) |
| External Python packages | N/A | None |

---

## Troubleshooting

**"rfkill: hard blocked"**
Your WiFi adapter is disabled at the hardware level. Check for a physical WiFi switch on your laptop, a keyboard Fn key combo, or a BIOS setting. If you're in a VM, some hypervisors force hard block — try USB passthrough or run on bare metal.

**"interface combinations are not supported"**
Your driver doesn't support virtual interfaces. airmon-nx handles this automatically via direct type conversion, but you'll lose the base station interface while in monitor mode.

**Channel/frequency errors**
airmon-nx validates against the hardware's supported channel list before attempting to set. If you see a regulatory domain error, set your region: `iw reg set US` (replace `US` with your country code).

**"No wireless interfaces found"**
Ensure your driver is loaded (`lsmod | grep <driver>`), the device isn't rfkill blocked, and `iw dev` shows output. For USB adapters, check `lsusb` and `dmesg` for connection issues.

---

## Contributing

This project aims to be a drop-in improvement over `airmon-ng`. If you find a driver quirk, hardware edge case, or process detection gap that isn't handled, please open an issue with:

- Output of `airmon-nx list -v`
- Output of `iw phy <phy> info`
- Your kernel version (`uname -r`)
- The driver and chipset involved

---

## License

Same license terms as the aircrack-ng suite this tool is designed to complement.