# HTWG VPN

[![Build](https://github.com/D4veDev/htwg-vpn/actions/workflows/build.yml/badge.svg)](https://github.com/D4veDev/htwg-vpn/actions/workflows/build.yml)

PySide6 GUI for OpenVPN at HTWG Konstanz with TOTP/MFA support.

---

## Requirements

- **OpenVPN Community** installed and on your system PATH
- **Python 3.12+** (only needed if building from source)
- **Windows**: no extra steps
- **macOS**: allow the app in System Settings > Privacy & Security after first launch
- **Linux**: install `libgl1`, `libxcb-cursor0`, and `libxkbcommon-x11-0` if not already present

---

## Usage

1. Download the latest binary for your platform from the [Releases](https://github.com/D4veDev/htwg-vpn/releases) page.
2. Run the executable (`htwg-vpn.exe` on Windows, `HTWG VPN.app` on macOS, `htwg-vpn` on Linux).
3. Follow the setup wizard to enter your HTWG credentials and TOTP secret.

---

## Build from Source

```bash
git clone https://github.com/D4veDev/htwg-vpn.git
cd htwg-vpn/GUI
pip install -r requirements.txt
pyinstaller htwg_vpn.spec
```

The built binary will be in the `dist/` folder.

---

## License

MIT
