"""
HTWG VPN — GUI (PySide6, cross-platform: Windows / macOS / Linux)

Architektur:
- GUI laeuft als normaler Benutzer (kein Admin/Root).
- Beim Verbinden wird NUR der openvpn-Prozess erhoeht gestartet:
    Windows : PowerShell Start-Process -Verb RunAs   (UAC-Prompt)
    Linux   : pkexec                                  (Polkit-Dialog)
    macOS   : osascript "with administrator privileges"
- Steuerung/Status laeuft danach ohne weitere Rechte ueber das
  OpenVPN-Management-Interface (127.0.0.1, passwortgeschuetzt).
  Trennen = "signal SIGTERM" ueber den Management-Socket -> kein
  zweiter Admin-Prompt noetig.

Konfiguration in .env neben der Anwendung:
    HTWG_USERNAME, HTWG_PASSWORD, HTWG_SEED, HTWG_OVPN (Pfad zur .ovpn)

Build (vom Nutzer selbst):
    pyinstaller --onefile --windowed --name htwg-vpn vpn_gui.py
"""

from __future__ import annotations

import json
import os
import platform
import secrets as pysecrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import cv2
import numpy as np
import pyotp
from dotenv import dotenv_values, set_key

from PySide6.QtCore import QEvent, QPointF, QRectF, Qt, QThread, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QFont,
    QGuiApplication,
    QIcon,
    QImage,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSystemTrayIcon,
    QToolButton,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

APP_NAME = "HTWG VPN"
MFA_ENROLL_URL = "https://mfa.rz.htwg-konstanz.de/#!/token/enroll///"

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = not IS_WINDOWS and not IS_MACOS

if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent

ENV_PATH = APP_DIR / ".env"
LOG_FILE = APP_DIR / "openvpn.log"
CREDS_PATH = APP_DIR / "vpn_secret.txt"
MGMT_PW_PATH = APP_DIR / "vpn_mgmt.pw"
STATE_PATH = APP_DIR / "vpn_session.json"

CREATE_NO_WINDOW = 0x08000000  # Windows


# ===================================================================
# Konfiguration (.env)
# ===================================================================
class EnvStore:
    """Liest/schreibt die .env neben der Anwendung."""

    KEYS = ("HTWG_USERNAME", "HTWG_PASSWORD", "HTWG_SEED", "HTWG_OVPN")

    def __init__(self, path: Path = ENV_PATH):
        self.path = path

    def load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        vals = dotenv_values(self.path, interpolate=False)
        return {k: v for k, v in vals.items() if v is not None}

    def get(self, key: str) -> str | None:
        v = self.load().get(key)
        if key == "HTWG_SEED" and v:
            v = v.replace(" ", "").upper()
        return v or None

    def set(self, key: str, value: str) -> None:
        if not self.path.exists():
            self.path.touch()
            if not IS_WINDOWS:
                os.chmod(self.path, 0o600)
        set_key(str(self.path), key, value)

    def delete(self, key: str) -> None:
        if not self.path.exists():
            return
        lines = self.path.read_text(encoding="utf-8").splitlines()
        kept = [l for l in lines if not l.strip().startswith(f"{key}=")]
        self.path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")

    def ovpn_path(self) -> Path | None:
        """Konfigurierte .ovpn, sonst erste .ovpn im App-Ordner."""
        cfg = self.get("HTWG_OVPN")
        if cfg and Path(cfg).exists():
            return Path(cfg)
        candidates = sorted(APP_DIR.glob("*.ovpn"))
        return candidates[0] if candidates else None

    def is_complete(self) -> bool:
        return all(self.get(k) for k in ("HTWG_USERNAME", "HTWG_PASSWORD", "HTWG_SEED")) \
            and self.ovpn_path() is not None
    
def app_log(msg: str) -> None:
    """Schreibt GUI-Ereignisse mit Zeitstempel in openvpn.log."""
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [GUI] {msg}\n")
    except OSError:
        pass


# ===================================================================
# TOTP
# ===================================================================
def otp_now(seed: str) -> tuple[str, int]:
    """(aktueller Code, Restsekunden im 30s-Fenster)"""
    remaining = 30 - int(time.time()) % 30
    return pyotp.TOTP(seed).now(), remaining


def otp_with_min_validity(seed: str, min_seconds: int, should_abort=None) -> str:
    """Wartet ggf. aufs naechste 30s-Fenster, damit der Code lange genug gilt."""
    code, remaining = otp_now(seed)
    if remaining < min_seconds:
        wait_until = time.time() + remaining + 1
        while time.time() < wait_until:
            if should_abort and should_abort():
                raise InterruptedError("Abgebrochen")
            time.sleep(0.2)
        code, _ = otp_now(seed)
    return code


# ===================================================================
# QR-Code -> Seed
# ===================================================================
def parse_otpauth_uri(data: str) -> tuple[str, str]:
    """(secret, token_label) aus einer otpauth://-URI."""
    if not data.startswith("otpauth://"):
        raise ValueError("Der QR-Code enthält keinen otpauth-Link.")
    parsed = urlparse(data)
    secret = parse_qs(parsed.query).get("secret", [None])[0]
    if not secret:
        raise ValueError("Im QR-Code fehlt der 'secret'-Parameter.")
    label = unquote(parsed.path.lstrip("/"))
    if ":" in label:
        label = label.split(":", 1)[1]
    return secret.replace(" ", "").upper(), label


def _decode_qr_bgr(img_bgr: np.ndarray) -> str:
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img_bgr)
    if not data:
        # zweiter Versuch: hochskalieren hilft bei kleinen QR-Grafiken
        big = cv2.resize(img_bgr, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        data, _, _ = detector.detectAndDecode(big)
    if not data:
        raise ValueError("Kein QR-Code im Bild erkannt.")
    return data


def _cap_qr_image(img: np.ndarray) -> np.ndarray:
    """Downscale images >2000 px on their longest side to prevent UI freezes."""
    h, w = img.shape[:2]
    if max(h, w) > 2000:
        scale = 2000 / max(h, w)
        img = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    return img


def decode_qr_from_file(path: Path) -> str:
    img = cv2.imread(str(path))
    if img is None:
        raise ValueError(f"Bilddatei nicht lesbar: {path.name}")
    return _decode_qr_bgr(_cap_qr_image(img))


def decode_qr_from_qimage(qimg: QImage) -> str:
    if qimg.isNull():
        raise ValueError("Die Zwischenablage enthält kein Bild.")
    qimg = qimg.convertToFormat(QImage.Format.Format_RGB888)
    h, w, bpl = qimg.height(), qimg.width(), qimg.bytesPerLine()
    arr = np.frombuffer(qimg.constBits(), dtype=np.uint8).reshape(h, bpl)
    rgb = arr[:, : w * 3].reshape(h, w, 3)
    return _decode_qr_bgr(_cap_qr_image(rgb[:, :, ::-1].copy()))  # RGB -> BGR


# ===================================================================
# OpenVPN finden + erhoeht starten (pro Plattform)
# ===================================================================
def find_openvpn() -> str | None:
    exe = shutil.which("openvpn")
    if exe:
        return exe
    candidates = []
    if IS_WINDOWS:
        candidates = [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
        ]
    else:
        candidates = [
            "/usr/sbin/openvpn", "/usr/local/sbin/openvpn",
            "/opt/homebrew/sbin/openvpn", "/usr/local/opt/openvpn/sbin/openvpn",
            "/usr/bin/openvpn",
        ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def pick_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_openvpn_args(ovpn: Path, mgmt_port: int) -> list[str]:
    args = [
        "--cd", str(ovpn.parent),
        "--config", str(ovpn),
        "--auth-user-pass", str(CREDS_PATH),
        "--auth-retry", "none",
        "--log-append", str(LOG_FILE),
        "--verb", "3",
        "--management", "127.0.0.1", str(mgmt_port), str(MGMT_PW_PATH),
    ]
    if IS_WINDOWS:
        args.append("--block-outside-dns")
    else:
        args.append("--daemon")
    return args


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"

def _ps_arg(s: str) -> str:
    """Argument für Start-Process -ArgumentList: doppelt gequotet wenn
    Leerzeichen enthalten sind, damit der Child-Prozess es als EIN Argument sieht."""
    if " " in s or "\t" in s or '"' in s:
        s = '"' + s.replace('"', '""') + '"'   # cmd-style doubling, kein Backslash-Escaping
    return "'" + s.replace("'", "''") + "'"


def launch_elevated(exe: str, args: list[str]) -> int:
    """Startet openvpn mit Adminrechten. Returns PID (0 wenn unbekannt).
    Wirft RuntimeError mit verstaendlicher Meldung bei Abbruch/Fehler."""
    if IS_WINDOWS:
        arg_list = ",".join(_ps_arg(a) for a in args)
        ps = (
            f"$p = Start-Process -FilePath {_ps_quote(exe)} "
            f"-ArgumentList @({arg_list}) -Verb RunAs -WindowStyle Hidden -PassThru; "
            f"$p.Id"
        )
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, creationflags=CREATE_NO_WINDOW,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Zeitüberschreitung beim Starten von OpenVPN (UAC-Dialog?)")
        if r.returncode != 0:
            stderr = r.stderr
            if ("cancel" in stderr.lower() or "abgebroch" in stderr.lower()
                    or "OperationCanceled" in stderr or "1223" in stderr):
                raise RuntimeError("Administratorrechte wurden abgelehnt (UAC abgebrochen).")
            raise RuntimeError(f"OpenVPN konnte nicht gestartet werden:\n{stderr.strip()[:300]}")
        try:
            return int(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return 0

    if IS_MACOS:
        shell_cmd = " ".join(shlex.quote(a) for a in [exe, *args])
        esc = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
        script = (
            f'do shell script "{esc}" with administrator privileges '
            f'with prompt "{APP_NAME} benötigt Administratorrechte, um die Verbindung aufzubauen."'
        )
        try:
            r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True,
                                timeout=60)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Zeitüberschreitung beim Administrator-Dialog (osascript)")
        if r.returncode != 0:
            if "User canceled" in r.stderr or "-128" in r.stderr:
                raise RuntimeError("Administratorrechte wurden abgelehnt.")
            raise RuntimeError(f"OpenVPN konnte nicht gestartet werden:\n{r.stderr.strip()[:300]}")
        return 0  # --daemon: PID unbekannt, Steuerung via Management-Socket

    # Linux
    if not shutil.which("pkexec"):
        raise RuntimeError(
            "pkexec wurde nicht gefunden (Paket 'polkit'). "
            "Bitte installieren oder OpenVPN manuell mit sudo starten."
        )
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise RuntimeError(
            "Kein grafischer Polkit-Agent erkannt. "
            "Bitte aus einem Desktop-Terminal starten oder das CLI-Skript verwenden."
        )
    try:
        r = subprocess.run(["pkexec", exe, *args], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Zeitüberschreitung beim Polkit-Dialog")
    if r.returncode == 126:
        raise RuntimeError("Administratorrechte wurden abgelehnt (Polkit-Dialog abgebrochen).")
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()[:300]
        raise RuntimeError(f"OpenVPN konnte nicht gestartet werden:\n{err}")
    return 0  # --daemon


# ===================================================================
# OpenVPN-Management-Interface (Status + Trennen ohne Adminrechte)
# ===================================================================
class MgmtClient:
    def __init__(self, port: int, password: str):
        self.port = port
        self.password = password
        self.sock: socket.socket | None = None
        self._buf = b""

    # --- low level -------------------------------------------------
    def _readline(self, timeout: float = 3.0) -> str:
        assert self.sock is not None
        end = time.time() + timeout
        while b"\n" not in self._buf:
            if time.time() > end:
                raise TimeoutError("Management-Interface antwortet nicht.")
            self.sock.settimeout(max(0.1, end - time.time()))
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Management-Verbindung geschlossen.")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").rstrip("\r")

    # --- API ---------------------------------------------------------
    def connect(self, timeout: float = 2.0) -> None:
        self.sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        self.sock.settimeout(timeout)
        # Passwort-Prompt kommt ohne Zeilenumbruch
        end = time.time() + 5
        while b"ENTER PASSWORD:" not in self._buf:
            if time.time() > end:
                raise TimeoutError("Kein Passwort-Prompt vom Management-Interface.")
            self._buf += self.sock.recv(4096)
        self._buf = b""
        self.sock.sendall((self.password + "\n").encode())
        # bis zur Erfolgsmeldung lesen
        end = time.time() + 5
        while time.time() < end:
            line = self._readline()
            if line.startswith("SUCCESS:"):
                self._buf = b""   # async events verwerfen, die vor dem ersten command() ankommen
                return
            if line.startswith("ERROR:"):
                raise PermissionError("Management-Passwort falsch.")
        raise TimeoutError("Anmeldung am Management-Interface fehlgeschlagen.")

    def command(self, cmd: str, timeout: float = 3.0) -> list[str]:
        assert self.sock is not None
        self.sock.sendall((cmd + "\n").encode())
        lines: list[str] = []
        end = time.time() + timeout
        while time.time() < end:
            line = self._readline(timeout=max(0.2, end - time.time()))
            if line.startswith(">"):       # asynchrone Realtime-Meldungen ignorieren
                continue
            if line == "END":
                return lines
            if line.startswith(("SUCCESS:", "ERROR:")):
                lines.append(line)
                return lines
            lines.append(line)
        raise TimeoutError("Management-Kommando ohne Antwort.")

    def state(self) -> tuple[str, str]:
        """(STATE, lokale_IP) — STATE z.B. CONNECTED, AUTH, WAIT, EXITING."""
        for line in self.command("state"):
            parts = line.split(",")
            if len(parts) >= 2 and parts[0].isdigit():
                ip = parts[3] if len(parts) > 3 else ""
                return parts[1], ip
        return "UNKNOWN", ""

    def disconnect_vpn(self) -> None:
        try:
            self.command("signal SIGTERM", timeout=2.0)
        except (TimeoutError, ConnectionError, OSError):
            pass  # Prozess beendet sich evtl. schneller als die Antwort kommt

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# ===================================================================
# Session-Datei (laufende Verbindung App-Neustarts ueberleben lassen)
# ===================================================================
def save_session(port: int, mgmt_pw: str, pid: int) -> None:
    STATE_PATH.write_text(json.dumps({"port": port, "pw": mgmt_pw, "pid": pid}))
    if not IS_WINDOWS:
        os.chmod(STATE_PATH, 0o600)


def load_session() -> dict | None:
    if not STATE_PATH.exists():
        return None
    try:
        d = json.loads(STATE_PATH.read_text())
        port = int(d.get("port", 0))
        pw = d.get("pw")
        if not (1 <= port <= 65535) or not isinstance(pw, str) or not pw:
            raise ValueError
        return {"port": port, "pw": pw, "pid": int(d.get("pid", 0))}
    except (json.JSONDecodeError, OSError, ValueError, TypeError):
        STATE_PATH.unlink(missing_ok=True)
        return None


def clear_session() -> None:
    STATE_PATH.unlink(missing_ok=True)
    MGMT_PW_PATH.unlink(missing_ok=True)


# ===================================================================
# Verbindungs-Worker (eigener Thread, blockiert die GUI nie)
# ===================================================================
class VpnWorker(QThread):
    """Baut die Verbindung auf (oder uebernimmt eine laufende Session)
    und ueberwacht sie bis zum Ende.

    Signale:
        state_changed(state, detail)  z.B. ("CONNECTED", "10.3.1.7")
        failed(meldung)               Fehler inkl. AUTH_FAILED
        ended()                       Verbindung beendet (sauber getrennt)
    """

    state_changed = Signal(str, str)
    failed = Signal(str)
    ended = Signal()

    def __init__(self, env: EnvStore, adopt: dict | None = None, parent=None):
        super().__init__(parent)
        self.env = env
        self.adopt = adopt          # {"port":..,"pw":..} -> laufende Session uebernehmen
        self._disconnect_requested = False
        self._got_connected = False

    def request_disconnect(self) -> None:
        self._disconnect_requested = True

    # ---------------------------------------------------------------
    def run(self) -> None:
        mgmt: MgmtClient | None = None
        try:
            if self.adopt:
                mgmt = MgmtClient(self.adopt["port"], self.adopt["pw"])
                try:
                    mgmt.connect(timeout=1.5)
                except (OSError, TimeoutError, PermissionError, ConnectionError):
                    clear_session()
                    self.ended.emit()
                    return
            else:
                mgmt = self._launch()
                if mgmt is None:
                    return  # failed() wurde bereits emittiert

            self._monitor(mgmt)
        finally:
            if mgmt:
                mgmt.close()
            CREDS_PATH.unlink(missing_ok=True)

    # ---------------------------------------------------------------
    def _launch(self) -> MgmtClient | None:
        exe = find_openvpn()
        if not exe:
            self.failed.emit(
                "OpenVPN wurde nicht gefunden.\n\n"
                "Bitte 'OpenVPN Community' installieren (nicht 'OpenVPN Connect') "
                "und ggf. den Pfad in den Einstellungen prüfen."
            )
            return None

        ovpn = self.env.ovpn_path()
        if not ovpn:
            self.failed.emit("Keine .ovpn-Datei gefunden. Bitte in den Einstellungen auswählen.")
            return None

        seed = self.env.get("HTWG_SEED")
        username = self.env.get("HTWG_USERNAME")
        password = self.env.get("HTWG_PASSWORD")
        if not (seed and username and password):
            self.failed.emit("Zugangsdaten unvollständig. Bitte die Einrichtung erneut durchlaufen.")
            return None

        # 1) OTP mit genug Restlaufzeit
        self.state_changed.emit("PREPARING", "")
        try:
            otp = otp_with_min_validity(seed, min_seconds=6,
                                        should_abort=lambda: self._disconnect_requested)
        except InterruptedError:
            self.ended.emit()
            return None

        # 2) Temporaere Dateien (Zugangsdaten + Management-Passwort)
        mgmt_pw = pysecrets.token_urlsafe(24)
        MGMT_PW_PATH.write_text(mgmt_pw + "\n")
        CREDS_PATH.write_text(f"{username}\n{password}{otp}\n")
        if not IS_WINDOWS:
            os.chmod(MGMT_PW_PATH, 0o600)
            os.chmod(CREDS_PATH, 0o600)

        # 3) Erhoeht starten (UAC / Polkit / osascript)
        port = pick_free_port()
        app_log("=" * 60)
        app_log(f"Verbindungsversuch ({platform.system()})  ovpn={ovpn.name}  port={port}")
        self.state_changed.emit("ELEVATING", "")
        try:
            pid = launch_elevated(exe, build_openvpn_args(ovpn, port))
        except RuntimeError as e:
            app_log(f"FEHLER bei Elevation: {e}")
            CREDS_PATH.unlink(missing_ok=True)
            MGMT_PW_PATH.unlink(missing_ok=True)
            self.failed.emit(str(e))
            return None

        save_session(port, mgmt_pw, pid)
        self.state_changed.emit("LAUNCHING", "")

        # 4) Auf das Management-Interface warten (max. 30 s)
        mgmt = MgmtClient(port, mgmt_pw)
        deadline = time.time() + 30
        while True:
            if self._disconnect_requested:
                clear_session()
                self.ended.emit()
                return None
            try:
                mgmt.connect(timeout=1.0)
                app_log(f"Management-Interface verbunden (PID {pid})")
                return mgmt
            except (OSError, TimeoutError, ConnectionError):
                if time.time() > deadline:
                    clear_session()
                    self.failed.emit(self._log_hint(
                        "OpenVPN hat nicht geantwortet (Start fehlgeschlagen?)."))
                    app_log("FEHLER: Management-Interface nicht erreichbar (30s Timeout)")
                    return None
                time.sleep(0.7)

    # ---------------------------------------------------------------
    def _monitor(self, mgmt: MgmtClient) -> None:
        last_state = ""
        while True:
            if self._disconnect_requested:
                self.state_changed.emit("EXITING", "")
                mgmt.disconnect_vpn()
                self._disconnect_requested = False  # nur einmal senden

            try:
                state, ip = mgmt.state()
            except (TimeoutError, ConnectionError, OSError):
                break  # Prozess weg -> unten auswerten

            if state != last_state:
                last_state = state
                if state == "CONNECTED":
                    self._got_connected = True
                    CREDS_PATH.unlink(missing_ok=True)
                self.state_changed.emit(state, ip)
                app_log(f"State: {state}" + (f"  IP {ip}" if ip else ""))

            time.sleep(1.0)

        clear_session()
        if not self._got_connected:
            self.failed.emit(self._log_hint("Verbindung fehlgeschlagen."))
        else:
            self.ended.emit()

    # ---------------------------------------------------------------
    @staticmethod
    def _log_hint(prefix: str) -> str:
        """Fehlertext mit konkretem Hinweis aus dem OpenVPN-Log anreichern."""
        try:
            tail = LOG_FILE.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = ""
        if "AUTH_FAILED" in tail:
            return (
                "Anmeldung fehlgeschlagen (AUTH_FAILED).\n\n"
                "Mögliche Ursachen:\n"
                "• MFA-Token noch nicht verifiziert → Menü 'Token verifizieren'\n"
                "• Falsches Passwort → Einstellungen prüfen\n"
                "• Systemuhr geht falsch (TOTP toleriert nur ±30 s)"
            )
        if "Cannot resolve host" in tail or "RESOLVE" in tail and "error" in tail.lower():
            return prefix + "\n\nDer VPN-Server konnte nicht aufgelöst werden — Internetverbindung prüfen."
        return prefix + f"\n\nDetails: Log ansehen ({LOG_FILE.name})."


# ===================================================================
# Design-System
# ===================================================================
THEME = {
    "bg":           "#13121F",
    "surface":      "#1C1B2E",
    "surface2":     "#252340",
    "border":       "#2E2B4A",
    "accent":       "#7B61FF",
    "accent_hover": "#9480FF",
    "accent_press": "#5B41DF",
    "green":        "#00C98D",
    "amber":        "#F5A623",
    "red":          "#E8473F",
    "red_hover":    "#FF5B52",
    "text":         "#F0EFF8",
    "text2":        "#9B98B8",
    "text3":        "#5C5878",
}

STATUS_COLORS = {
    "off":   THEME["text3"],
    "busy":  THEME["amber"],
    "on":    THEME["green"],
    "error": THEME["red"],
}

_MONO = "Consolas" if IS_WINDOWS else ("Menlo" if IS_MACOS else "Ubuntu Mono")
_UI   = "'Segoe UI'" if IS_WINDOWS else ("'-apple-system'" if IS_MACOS else "'Inter', 'Ubuntu'")

GLOBAL_STYLE = f"""
/* ── Base ─────────────────────────────────────────────── */
QWidget {{
    background-color: {THEME["bg"]};
    color: {THEME["text"]};
    font-family: {_UI}, Arial, sans-serif;
    font-size: 13px;
}}
QLabel  {{ background: transparent; }}
QCheckBox {{ background: transparent; spacing: 6px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {THEME["border"]};
    border-radius: 4px;
    background: {THEME["surface"]};
}}
QCheckBox::indicator:checked {{
    background: {THEME["accent"]};
    border-color: {THEME["accent"]};
    image: none;
}}

/* ── Buttons ───────────────────────────────────────────── */
QPushButton {{
    background-color: {THEME["accent"]};
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 7px 16px;
    font-weight: 600;
    font-size: 13px;
}}
QPushButton:hover   {{ background-color: {THEME["accent_hover"]}; }}
QPushButton:pressed {{ background-color: {THEME["accent_press"]}; }}
QPushButton:disabled {{ background-color: {THEME["surface2"]}; color: {THEME["text3"]}; }}

QPushButton#connectBtn {{
    font-size: 15px;
    font-weight: 700;
    border-radius: 10px;
    letter-spacing: 1px;
    padding: 0px;
}}
QPushButton#ghostBtn {{
    background: transparent;
    color: {THEME["text2"]};
    border: 1px solid {THEME["border"]};
    border-radius: 7px;
    padding: 5px 12px;
    font-weight: 500;
}}
QPushButton#ghostBtn:hover {{
    background: {THEME["surface"]};
    color: {THEME["text"]};
    border-color: {THEME["accent"]};
}}
QPushButton#iconBtn {{
    background: transparent;
    border: none;
    border-radius: 6px;
    color: {THEME["text2"]};
    font-size: 18px;
    padding: 2px;
}}
QPushButton#iconBtn:hover {{ background: {THEME["surface2"]}; color: {THEME["text"]}; }}

/* ── Inputs ────────────────────────────────────────────── */
QLineEdit {{
    background-color: {THEME["surface"]};
    border: 1px solid {THEME["border"]};
    border-radius: 7px;
    padding: 8px 10px;
    color: {THEME["text"]};
    selection-background-color: {THEME["accent"]};
}}
QLineEdit:focus  {{ border-color: {THEME["accent"]}; }}
QLineEdit:read-only {{ color: {THEME["text2"]}; }}

QToolButton {{
    background: transparent;
    border: none;
    color: {THEME["text2"]};
    font-size: 16px;
    padding: 4px 6px;
    border-radius: 5px;
}}
QToolButton:hover {{ background: {THEME["surface2"]}; color: {THEME["text"]}; }}

/* ── Progress bar ──────────────────────────────────────── */
QProgressBar {{
    background: {THEME["surface2"]};
    border: none;
    border-radius: 3px;
    max-height: 5px;
}}
QProgressBar::chunk {{ border-radius: 3px; }}

/* ── Scroll bars ───────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {THEME["border"]};
    border-radius: 3px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: {THEME["text3"]}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}

/* ── Text view (log) ───────────────────────────────────── */
QPlainTextEdit {{
    background: #0C0B18;
    border: 1px solid {THEME["border"]};
    border-radius: 8px;
    color: {THEME["text2"]};
    selection-background-color: {THEME["accent"]};
    font-size: 12px;
}}

/* ── Cards ─────────────────────────────────────────────── */
QFrame#card {{
    background: {THEME["surface"]};
    border: 1px solid {THEME["border"]};
    border-radius: 12px;
}}

/* ── Dialogs ───────────────────────────────────────────── */
QDialog {{ background: {THEME["bg"]}; }}
QMessageBox {{ background: {THEME["surface"]}; }}
QMessageBox QLabel {{ color: {THEME["text"]}; }}

/* ── Wizard ────────────────────────────────────────────── */
QWizard          {{ background: {THEME["bg"]}; }}
QWizardPage      {{ background: {THEME["bg"]}; }}
QWizard QLabel   {{ color: {THEME["text"]}; }}

/* ── Form labels ───────────────────────────────────────── */
QFormLayout QLabel {{ color: {THEME["text2"]}; }}

/* ── Menus ─────────────────────────────────────────────── */
QMenu {{
    background: {THEME["surface"]};
    border: 1px solid {THEME["border"]};
    border-radius: 8px;
    padding: 4px;
    color: {THEME["text"]};
}}
QMenu::item {{
    padding: 7px 28px 7px 14px;
    border-radius: 5px;
}}
QMenu::item:selected {{ background: {THEME["accent"]}; color: #fff; }}
QMenu::separator {{ height: 1px; background: {THEME["border"]}; margin: 4px 8px; }}

/* ── Dialog buttons ────────────────────────────────────── */
QDialogButtonBox QPushButton {{
    min-width: 80px;
}}
"""


def _draw_shield(p: QPainter, cx: float, cy: float, r: float, color: QColor) -> None:
    """Draw a shield centered at (cx,cy) with radius r."""
    pts = [
        QPointF(cx,          cy - r),
        QPointF(cx + r*0.82, cy - r*0.55),
        QPointF(cx + r*0.82, cy + r*0.20),
        QPointF(cx,          cy + r),
        QPointF(cx - r*0.82, cy + r*0.20),
        QPointF(cx - r*0.82, cy - r*0.55),
    ]
    poly = QPolygonF(pts)

    fill = QColor(color)
    fill.setAlpha(22)
    p.setBrush(QBrush(fill))
    pen = QPen(color, r * 0.09)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPolygon(poly)

    # Lock body
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(color))
    bx = cx - r * 0.22
    by = cy + r * 0.10
    bw = r * 0.44
    bh = r * 0.36
    p.drawRoundedRect(QRectF(bx, by, bw, bh), r * 0.06, r * 0.06)

    # Keyhole dot
    hole = QColor(THEME["bg"])
    p.setBrush(QBrush(hole))
    p.drawEllipse(QRectF(cx - r*0.08, by + r*0.05, r*0.16, r*0.16))

    # Shackle arc
    p.setPen(QPen(color, r * 0.10, Qt.PenStyle.SolidLine,
                  Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawArc(QRectF(cx - r*0.22, cy - r*0.22, r*0.44, r*0.38), 0, 180 * 16)


def make_shield_pixmap(color_key: str, size: int) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    _draw_shield(p, size / 2, size / 2, size * 0.40, QColor(STATUS_COLORS[color_key]))
    p.end()
    return pm


def make_shield_icon(color_key: str) -> QIcon:
    return QIcon(make_shield_pixmap(color_key, 64))


# ===================================================================
# OTP-Anzeige (Code gross + Countdown), wiederverwendbar
# ===================================================================
class OtpWidget(QWidget):
    def __init__(self, env: EnvStore, auto_copy: bool = False, parent=None):
        super().__init__(parent)
        self.env = env
        self._last_code = ""

        self.code_label = QLabel("––– –––")
        self.code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.code_label.setStyleSheet(f"""
        QLabel {{
            font-family: '{_MONO}';
            font-size: 30px;
            font-weight: bold;
            letter-spacing: 4px;
            color: {THEME['text']};
            background: transparent;
        }}
    """)

        self.countdown_label = QLabel("30s")
        self.countdown_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.countdown_label.setStyleSheet(f"color: {THEME['text3']}; font-size: 11px; background: transparent;")

        self.bar = QProgressBar()
        self.bar.setRange(0, 30)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(4)

        self.copy_btn = QPushButton("Kopieren")
        self.copy_btn.setObjectName("ghostBtn")
        self.copy_btn.setFixedHeight(30)
        self.copy_btn.clicked.connect(self.copy_code)

        self.auto_copy_cb = QCheckBox("Auto-kopieren")
        self.auto_copy_cb.setChecked(auto_copy)
        self.auto_copy_cb.setVisible(auto_copy)

        bar_row = QHBoxLayout()
        bar_row.setSpacing(8)
        bar_row.addWidget(self.bar, stretch=1)
        bar_row.addWidget(self.countdown_label)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.copy_btn)
        btn_row.addWidget(self.auto_copy_cb)
        btn_row.addStretch(1)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        lay.addWidget(self.code_label)
        lay.addLayout(bar_row)
        lay.addLayout(btn_row)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(500)
        self.refresh()

    def refresh(self) -> None:
        seed = self.env.get("HTWG_SEED")
        if not seed:
            self.code_label.setText("––– –––")
            self.bar.setValue(0)
            self.countdown_label.setText("–")
            return
        code, remaining = otp_now(seed)
        self.code_label.setText(f"{code[:3]} {code[3:]}")
        self.bar.setValue(remaining)
        self.countdown_label.setText(f"{remaining}s")
        chunk_color = THEME["red"] if remaining <= 7 else THEME["green"]
        self.bar.setStyleSheet(f"QProgressBar::chunk {{ background: {chunk_color}; border-radius: 3px; }}")
        if code != self._last_code:
            self._last_code = code
            if self.auto_copy_cb.isChecked():
                QGuiApplication.clipboard().setText(code)

    def copy_code(self) -> None:
        if self._last_code:
            QGuiApplication.clipboard().setText(self._last_code)
            self.copy_btn.setText("Kopiert ✓")
            QTimer.singleShot(1500, lambda: self.copy_btn.setText("Kopieren"))


# ===================================================================
# Setup-Assistent (erster Start)
# ===================================================================
class PageChecks(QWizardPage):
    """Schritt 1: Voraussetzungen + .ovpn waehlen."""

    def __init__(self, env: EnvStore):
        super().__init__()
        self.env = env
        self.setTitle("Willkommen")
        self.setSubTitle(
            "Voraussetzung: aktiver HTWG-Account mit VPN-Berechtigung "
            "und bereits eingerichteter MFA-App (z. B. Google Authenticator)."
        )
        self.ovpn_path: Path | None = env.ovpn_path()

        self.openvpn_label = QLabel()
        self.ovpn_label = QLabel()
        self.ovpn_label.setWordWrap(True)
        pick = QPushButton(".ovpn-Datei auswählen…")
        pick.clicked.connect(self.pick_ovpn)

        hint = QLabel(
            'Die aktuelle .ovpn-Datei gibt es beim '
            '<a href="https://www.htwg-konstanz.de/hochschule/einrichtungen/rechenzentrum/dienste/vpn-verbindung/">HTWG-Rechenzentrum</a>.'
        )
        hint.setOpenExternalLinks(True)
        hint.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.addWidget(self.openvpn_label)
        lay.addSpacing(10)
        lay.addWidget(self.ovpn_label)
        lay.addWidget(pick)
        lay.addWidget(hint)
        lay.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        exe = find_openvpn()
        self.openvpn_label.setText(
            f"✓ OpenVPN gefunden: {exe}" if exe else
            "✗ OpenVPN wurde nicht gefunden.\n"
            "   Bitte 'OpenVPN Community' installieren (nicht 'OpenVPN Connect')."
        )
        self.ovpn_label.setText(
            f"✓ Konfigurationsdatei: {self.ovpn_path.name}" if self.ovpn_path else
            "✗ Keine .ovpn-Datei im Programmordner gefunden."
        )
        self.completeChanged.emit()

    def pick_ovpn(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(
            self, "OpenVPN-Konfiguration auswählen", str(APP_DIR), "OpenVPN-Konfiguration (*.ovpn)")
        if fn:
            self.ovpn_path = Path(fn)
            self.refresh()

    def isComplete(self) -> bool:
        return find_openvpn() is not None and self.ovpn_path is not None

    def validatePage(self) -> bool:
        return True  # env write deferred to SetupWizard.accept()


class PageCredentials(QWizardPage):
    """Schritt 2: RZ-Account."""

    def __init__(self, env: EnvStore):
        super().__init__()
        self.env = env
        self.setTitle("HTWG-Zugangsdaten")
        self.setSubTitle("Dein RZ-Account (wie für E-Mail und LSF).")

        self.user_edit = QLineEdit(env.get("HTWG_USERNAME") or "")
        self.user_edit.setPlaceholderText("z. B. da211bre")
        self.pw_edit = QLineEdit(env.get("HTWG_PASSWORD") or "")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        eye = QToolButton()
        eye.setText("👁")
        eye.setCheckable(True)
        eye.toggled.connect(lambda on: self.pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        pw_row = QHBoxLayout()
        pw_row.addWidget(self.pw_edit)
        pw_row.addWidget(eye)

        form = QFormLayout(self)
        form.addRow("Benutzername", self.user_edit)
        form.addRow("Passwort", pw_row)
        note = QLabel("Die Daten werden lokal in der Datei .env neben dem Programm gespeichert.")
        note.setWordWrap(True)
        form.addRow(note)

        self.user_edit.textChanged.connect(self.completeChanged)
        self.pw_edit.textChanged.connect(self.completeChanged)

    def isComplete(self) -> bool:
        return bool(self.user_edit.text().strip()) and bool(self.pw_edit.text())

    def validatePage(self) -> bool:
        return True  # env write deferred to SetupWizard.accept()


class PageEnroll(QWizardPage):
    """Schritt 3: Token im Portal anlegen, QR einlesen."""

    def __init__(self, env: EnvStore):
        super().__init__()
        self.env = env
        self.setTitle("MFA-Token anlegen")
        self.setSubTitle("Ein neuer Software-Token nur für dieses Programm.")
        self.seed: str | None = env.get("HTWG_SEED")
        self.token_label = ""

        steps = QLabel(
            "1. Portal mit VPN öffnen und mit RZ-Account anmelden (Benutzername + Passwort + OTP der App)\n"
            "2. \n"
            "2. Kurze Beschreibung eingeben (z. B. „Laptop“) und „Token ausrollen“ klicken\n"
            "3. Rechtsklick auf den QR-Code → „Grafik kopieren“\n"
            "4. Hier auf „QR aus Zwischenablage einlesen“ klicken"
        )
        steps.setWordWrap(True)

        open_btn = QPushButton("MFA-Portal im Browser öffnen")
        open_btn.clicked.connect(lambda: webbrowser.open(MFA_ENROLL_URL))

        clip_btn = QPushButton("QR aus Zwischenablage einlesen")
        clip_btn.clicked.connect(self.read_clipboard)
        file_btn = QPushButton("QR-Bilddatei auswählen…")
        file_btn.clicked.connect(self.read_file)

        self.status = QLabel("Noch kein QR-Code eingelesen." if not self.seed
                             else "✓ Vorhandener Token aus .env übernommen.")
        self.status.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.addWidget(steps)
        lay.addWidget(open_btn)
        row = QHBoxLayout()
        row.addWidget(clip_btn)
        row.addWidget(file_btn)
        lay.addLayout(row)
        lay.addWidget(self.status)
        lay.addStretch(1)

    def _apply(self, data: str) -> None:
        seed, label = parse_otpauth_uri(data)
        self.seed, self.token_label = seed, label
        self.status.setText(f"✓ QR-Code erkannt — Token „{label or 'unbenannt'}“ übernommen.")
        self.completeChanged.emit()

    def read_clipboard(self) -> None:
        try:
            self._apply(decode_qr_from_qimage(QGuiApplication.clipboard().image()))
        except ValueError as e:
            self.status.setText(f"✗ {e}\nTipp: Rechtsklick auf den QR → „Grafik kopieren“, dann erneut versuchen.")

    def read_file(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "QR-Code-Bild auswählen", str(Path.home()),
                                            "Bilder (*.png *.jpg *.jpeg *.bmp)")
        if not fn:
            return
        try:
            self._apply(decode_qr_from_file(Path(fn)))
        except ValueError as e:
            self.status.setText(f"✗ {e}")

    def isComplete(self) -> bool:
        return self.seed is not None

    def validatePage(self) -> bool:
        return True  # env write deferred to SetupWizard.accept()


class PageVerify(QWizardPage):
    """Schritt 4: OTP im Portal bestaetigen."""

    def __init__(self, env: EnvStore):
        super().__init__()
        self.setTitle("Token verifizieren")
        self.setSubTitle("Letzter Schritt — zurück im Browser.")
        info = QLabel(
            "Im Portal ist jetzt das Feld „Please enter a valid OTP value of the new token.“\n\n"
            "Der aktuelle Code liegt bereits in der Zwischenablage:\n"
            "einfügen (Strg+V) und „Token verifizieren“ klicken.\n"
            "Danach hier auf „Fertigstellen“."
        )
        info.setWordWrap(True)
        self.otp = OtpWidget(env, auto_copy=True)
        lay = QVBoxLayout(self)
        lay.addWidget(info)
        lay.addSpacing(8)
        lay.addWidget(self.otp)
        lay.addStretch(1)


class SetupWizard(QWizard):
    def __init__(self, env: EnvStore, parent=None):
        super().__init__(parent)
        self._env = env
        self.setWindowTitle(f"{APP_NAME} — Einrichtung")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(560, 420)
        self._p_checks = PageChecks(env)
        self._p_creds = PageCredentials(env)
        self._p_enroll = PageEnroll(env)
        self.addPage(self._p_checks)
        self.addPage(self._p_creds)
        self.addPage(self._p_enroll)
        self.addPage(PageVerify(env))
        self.setButtonText(QWizard.WizardButton.NextButton, "Weiter")
        self.setButtonText(QWizard.WizardButton.BackButton, "Zurück")
        self.setButtonText(QWizard.WizardButton.FinishButton, "Fertigstellen")
        self.setButtonText(QWizard.WizardButton.CancelButton, "Abbrechen")

    def accept(self) -> None:
        """Write all wizard fields to .env atomically on finish (not per-page)."""
        if self._p_checks.ovpn_path:
            self._env.set("HTWG_OVPN", str(self._p_checks.ovpn_path))
        self._env.set("HTWG_USERNAME", self._p_creds.user_edit.text().strip())
        self._env.set("HTWG_PASSWORD", self._p_creds.pw_edit.text())
        if self._p_enroll.seed:
            self._env.set("HTWG_SEED", self._p_enroll.seed)
        super().accept()


# ===================================================================
# Dialoge: Verifizieren / Einstellungen / Log
# ===================================================================
def _section_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setStyleSheet(
        f"color: {THEME['text3']}; font-size: 10px; font-weight: 700; "
        f"letter-spacing: 1px; background: transparent;"
    )
    return lbl


class VerifyDialog(QDialog):
    def __init__(self, env: EnvStore, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Token verifizieren")
        self.setMinimumWidth(460)

        title = QLabel("MFA-Token verifizieren")
        title.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {THEME['text']}; background: transparent;")

        info = QLabel(
            "Öffne das MFA-Portal, füge den Code ein (liegt in der Zwischenablage)\n"
            "und klicke 'Token verifizieren'."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {THEME['text2']}; background: transparent;")

        open_btn = QPushButton("MFA-Portal öffnen")
        open_btn.clicked.connect(lambda: webbrowser.open(MFA_ENROLL_URL))

        otp_card = QFrame()
        otp_card.setObjectName("card")
        otp_inner = QVBoxLayout(otp_card)
        otp_inner.setContentsMargins(16, 14, 16, 14)
        otp_inner.addWidget(_section_label("Aktueller Code"))
        otp_inner.addSpacing(4)
        otp_inner.addWidget(OtpWidget(env, auto_copy=True))

        close_btn = QPushButton("Fertig — im Browser bestätigt")
        close_btn.clicked.connect(self.accept)
        close_btn.setObjectName("ghostBtn")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addWidget(title)
        lay.addWidget(info)
        lay.addWidget(open_btn)
        lay.addWidget(otp_card)
        lay.addSpacing(4)
        lay.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)


class SettingsDialog(QDialog):
    token_reset = Signal()

    def __init__(self, env: EnvStore, parent=None):
        super().__init__(parent)
        self.env = env
        self.setWindowTitle("Einstellungen")
        self.setMinimumWidth(500)

        title = QLabel("Einstellungen")
        title.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {THEME['text']}; background: transparent;")

        # ── Credentials card ──────────────────────────────────────
        cred_card = QFrame()
        cred_card.setObjectName("card")
        cred_inner = QVBoxLayout(cred_card)
        cred_inner.setContentsMargins(16, 14, 16, 14)
        cred_inner.setSpacing(10)
        cred_inner.addWidget(_section_label("RZ-Zugangsdaten"))
        cred_inner.addSpacing(2)

        self.user_edit = QLineEdit(env.get("HTWG_USERNAME") or "")
        self.user_edit.setPlaceholderText("Benutzername (z. B. da211bre)")
        self.pw_edit = QLineEdit(env.get("HTWG_PASSWORD") or "")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_edit.setPlaceholderText("Passwort")
        eye = QToolButton()
        eye.setText("👁")
        eye.setCheckable(True)
        eye.toggled.connect(lambda on: self.pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        pw_row = QHBoxLayout()
        pw_row.setSpacing(6)
        pw_row.addWidget(self.pw_edit)
        pw_row.addWidget(eye)

        cred_form = QFormLayout()
        cred_form.setSpacing(8)
        cred_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        cred_form.addRow("Benutzername", self.user_edit)
        cred_form.addRow("Passwort", pw_row)
        cred_inner.addLayout(cred_form)

        # ── VPN config card ───────────────────────────────────────
        cfg_card = QFrame()
        cfg_card.setObjectName("card")
        cfg_inner = QVBoxLayout(cfg_card)
        cfg_inner.setContentsMargins(16, 14, 16, 14)
        cfg_inner.setSpacing(10)
        cfg_inner.addWidget(_section_label("VPN-Konfiguration"))
        cfg_inner.addSpacing(2)

        ovpn = env.ovpn_path()
        self.ovpn_edit = QLineEdit(str(ovpn) if ovpn else "")
        self.ovpn_edit.setReadOnly(True)
        self.ovpn_edit.setPlaceholderText("Keine .ovpn-Datei gewählt")
        pick = QPushButton("Ändern…")
        pick.clicked.connect(self.pick_ovpn)
        ovpn_row = QHBoxLayout()
        ovpn_row.setSpacing(6)
        ovpn_row.addWidget(self.ovpn_edit)
        ovpn_row.addWidget(pick)

        cfg_inner.addWidget(QLabel(".ovpn-Datei"))
        cfg_inner.addLayout(ovpn_row)

        # ── Danger zone ───────────────────────────────────────────
        reset_btn = QPushButton("MFA-Token zurücksetzen…")
        reset_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {THEME['red']}; "
            f"border: 1px solid {THEME['red']}; border-radius: 8px; padding: 7px 16px; font-weight: 600; }}"
            f"QPushButton:hover {{ background: {THEME['red']}; color: #fff; }}"
        )
        reset_btn.clicked.connect(self.reset_token)

        # ── Buttons ───────────────────────────────────────────────
        save_btn = QPushButton("Speichern")
        cancel_btn = QPushButton("Abbrechen")
        cancel_btn.setObjectName("ghostBtn")
        save_btn.clicked.connect(self.save)
        cancel_btn.clicked.connect(self.reject)
        btn_row = QHBoxLayout()
        btn_row.addWidget(cancel_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(save_btn)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addWidget(title)
        lay.addWidget(cred_card)
        lay.addWidget(cfg_card)
        lay.addWidget(reset_btn)
        lay.addSpacing(4)
        lay.addLayout(btn_row)

    def pick_ovpn(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "OpenVPN-Konfiguration auswählen",
                                            str(APP_DIR), "OpenVPN-Konfiguration (*.ovpn)")
        if fn:
            self.ovpn_edit.setText(fn)

    def save(self) -> None:
        if not self.user_edit.text().strip() or not self.pw_edit.text():
            QMessageBox.warning(self, "Einstellungen", "Benutzername und Passwort dürfen nicht leer sein.")
            return
        self.env.set("HTWG_USERNAME", self.user_edit.text().strip())
        self.env.set("HTWG_PASSWORD", self.pw_edit.text())
        if self.ovpn_edit.text():
            self.env.set("HTWG_OVPN", self.ovpn_edit.text())
        self.accept()

    def reset_token(self) -> None:
        ok = QMessageBox.question(
            self, "Token zurücksetzen",
            "Der gespeicherte MFA-Token wird gelöscht und die Einrichtung startet neu.\n"
            "Der alte Token sollte danach auch im HTWG-Portal entfernt werden.\n\nFortfahren?")
        if ok == QMessageBox.StandardButton.Yes:
            self.env.delete("HTWG_SEED")
            self.token_reset.emit()
            self.accept()


class LogDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("OpenVPN-Protokoll")
        self.resize(760, 500)

        title = QLabel("OpenVPN-Protokoll")
        title.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {THEME['text']}; background: transparent;")

        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        mono = QFont(_MONO)
        mono.setPointSize(11)
        self.text.setFont(mono)

        close_btn = QPushButton("Schließen")
        close_btn.setObjectName("ghostBtn")
        close_btn.clicked.connect(self.close)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)
        lay.addWidget(title)
        lay.addWidget(self.text)
        lay.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.refresh()

    def refresh(self) -> None:
        try:
            with LOG_FILE.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                tail = min(size, 100_000)
                f.seek(size - tail)
                raw = f.read()
            prefix = f"[... {size // 1024} KB gesamt, zeige letzte 100 KB ...]\n\n" if tail < size else ""
            content = prefix + raw.decode("utf-8", "replace")
        except OSError:
            content = f"Noch keine Einträge.\n\nErwarteter Pfad:\n{LOG_FILE}"
        if content != self.text.toPlainText():
            sb = self.text.verticalScrollBar()
            at_bottom = sb.value() >= sb.maximum() - 4
            self.text.setPlainText(content)
            if at_bottom:
                sb.setValue(sb.maximum())


# ===================================================================
# Hauptfenster + Tray
# ===================================================================
STATE_TEXT = {
    "PREPARING":    ("busy", "Wird vorbereitet",         "OTP-Code wird generiert…"),
    "ELEVATING":    ("busy", "Warte auf Bestätigung",    "Administratorrechte erforderlich"),
    "LAUNCHING":    ("busy", "Starte OpenVPN",           ""),
    "CONNECTING":   ("busy", "Verbinde",                 ""),
    "WAIT":         ("busy", "Verbinde",                 ""),
    "AUTH":         ("busy", "Authentifiziere",          ""),
    "GET_CONFIG":   ("busy", "Lade Konfiguration",       ""),
    "ASSIGN_IP":    ("busy", "Beziehe IP-Adresse",       ""),
    "ADD_ROUTES":   ("busy", "Richte Netzwerk ein",      ""),
    "TCP_CONNECT":  ("busy", "Verbinde",                 ""),
    "RESOLVE":      ("busy", "Verbinde",                 ""),
    "RECONNECTING": ("busy", "Verbindet neu",            ""),
    "CONNECTED":    ("on",   "Verbunden",                ""),
    "EXITING":      ("busy", "Trenne",                   ""),
    "DISCONNECTED": ("off",  "Nicht verbunden",          "Kein Schutz aktiv"),
}


class MainWindow(QWidget):
    def __init__(self, env: EnvStore):
        super().__init__()
        self.env = env
        self.worker: VpnWorker | None = None
        self.connected_since: float | None = None
        self._quitting = False
        self._current_state = "DISCONNECTED"
        self._has_tray = QSystemTrayIcon.isSystemTrayAvailable()

        self.setWindowTitle(APP_NAME)
        self.setMinimumWidth(400)
        self.setMinimumHeight(560)

        if not self._has_tray:
            QMessageBox.information(self, APP_NAME,
                "Kein System-Tray verfügbar — die App wird sich beim Schließen "
                "des Fensters komplett beenden.")

        self._build_ui()
        self._build_tray()
        self._set_state("DISCONNECTED", "")

        sess = load_session()
        if sess:
            self._start_worker(adopt=sess)

    # ---------------------------------------------------------------
    def _build_ui(self) -> None:
        # ── Header ────────────────────────────────────────────────
        app_lbl = QLabel(APP_NAME)
        app_lbl.setStyleSheet(
            f"font-size: 15px; font-weight: 700; color: {THEME['text']}; background: transparent;"
        )
        settings_btn = QPushButton("⚙")
        settings_btn.setObjectName("iconBtn")
        settings_btn.setFixedSize(32, 32)
        settings_btn.setToolTip("Einstellungen")
        settings_btn.clicked.connect(self.open_settings)

        header = QHBoxLayout()
        header.addWidget(app_lbl)
        header.addStretch(1)
        header.addWidget(settings_btn)

        # ── Status card ────────────────────────────────────────────
        self.shield_label = QLabel()
        self.shield_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.shield_label.setFixedSize(100, 100)
        self.shield_label.setStyleSheet("background: transparent;")

        self.status_label = QLabel("Nicht verbunden")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet(
            f"font-size: 20px; font-weight: 700; color: {THEME['text']}; background: transparent;"
        )

        self.detail_label = QLabel("")
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_label.setStyleSheet(
            f"font-size: 12px; color: {THEME['text2']}; background: transparent;"
        )

        status_card = QFrame()
        status_card.setObjectName("card")
        sc_lay = QVBoxLayout(status_card)
        sc_lay.setContentsMargins(16, 24, 16, 24)
        sc_lay.setSpacing(6)
        sc_lay.addWidget(self.shield_label, alignment=Qt.AlignmentFlag.AlignCenter)
        sc_lay.addSpacing(8)
        sc_lay.addWidget(self.status_label)
        sc_lay.addWidget(self.detail_label)

        # ── OTP card ───────────────────────────────────────────────
        otp_card = QFrame()
        otp_card.setObjectName("card")
        otp_lay = QVBoxLayout(otp_card)
        otp_lay.setContentsMargins(16, 14, 16, 14)
        otp_lay.setSpacing(8)
        otp_lay.addWidget(_section_label("Einmal-Code (OTP)"))
        otp_lay.addSpacing(2)
        self.otp_widget = OtpWidget(self.env)
        otp_lay.addWidget(self.otp_widget)

        # ── Connect button ─────────────────────────────────────────
        self.toggle_btn = QPushButton("Verbinden")
        self.toggle_btn.setObjectName("connectBtn")
        self.toggle_btn.setMinimumHeight(52)
        self.toggle_btn.clicked.connect(self.toggle)

        # ── Footer ─────────────────────────────────────────────────
        log_btn = QPushButton("Protokoll")
        log_btn.setObjectName("ghostBtn")
        log_btn.clicked.connect(lambda: LogDialog(self).show())

        verify_btn = QPushButton("Token verifizieren")
        verify_btn.setObjectName("ghostBtn")
        verify_btn.clicked.connect(lambda: VerifyDialog(self.env, self).exec())

        min_btn = QPushButton("Minimieren")
        min_btn.setObjectName("ghostBtn")
        min_btn.setToolTip("Fenster ausblenden — Programm läuft im Tray weiter")
        min_btn.clicked.connect(self.hide)
        min_btn.setVisible(self._has_tray)

        footer = QHBoxLayout()
        footer.setSpacing(8)
        footer.addWidget(min_btn)
        footer.addWidget(log_btn)
        footer.addStretch(1)
        footer.addWidget(verify_btn)

        # ── Assemble ───────────────────────────────────────────────
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(12)
        lay.addLayout(header)
        lay.addWidget(status_card)
        lay.addWidget(otp_card)
        lay.addWidget(self.toggle_btn)
        lay.addLayout(footer)

        self.uptime_timer = QTimer(self)
        self.uptime_timer.timeout.connect(self._update_uptime)
        self.uptime_timer.start(1000)

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(make_shield_icon("off"), self)
        self.tray.setToolTip(f"{APP_NAME} — Nicht verbunden")
        menu = QMenu()
        self.tray_toggle = QAction("Verbinden", self)
        self.tray_toggle.triggered.connect(self.toggle)
        show_action = QAction("Fenster anzeigen", self)
        show_action.triggered.connect(self.show_window)
        quit_action = QAction("Beenden", self)
        quit_action.triggered.connect(self.quit_app)
        menu.addAction(self.tray_toggle)
        menu.addSeparator()
        menu.addAction(show_action)
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: self.show_window()
            if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        if self._has_tray:
            self.tray.show()

    # ---------------------------------------------------------------
    def show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event) -> None:
        if self._is_connected_or_busy() and self.worker:
            self.worker.request_disconnect()
            self.worker.wait(8000)
        self._quitting = True
        if self._has_tray:
            self.tray.hide()
        QApplication.quit()
        event.accept()

    def quit_app(self) -> None:
        self.close()

    # ---------------------------------------------------------------
    def _is_connected_or_busy(self) -> bool:
        return self.worker is not None and self.worker.isRunning()

    def toggle(self) -> None:
        if self._is_connected_or_busy():
            self.worker.request_disconnect()
            self.toggle_btn.setEnabled(False)
            return
        if not self.env.is_complete():
            QMessageBox.information(
                self, APP_NAME,
                "Die Einrichtung ist unvollständig — der Assistent startet jetzt.")
            self._run_wizard()
            if not self.env.is_complete():
                return
        self._start_worker()

    def _start_worker(self, adopt: dict | None = None) -> None:
        self.worker = VpnWorker(self.env, adopt=adopt)
        self.worker.state_changed.connect(self._set_state)
        self.worker.failed.connect(self._on_failed)
        self.worker.ended.connect(lambda: self._set_state("DISCONNECTED", ""))
        self.worker.finished.connect(self._on_worker_finished)
        self._set_state("LAUNCHING" if adopt else "PREPARING", "")
        self.worker.start()

    def _on_worker_finished(self) -> None:
        if self.worker:
            self.worker.deleteLater()
        self.worker = None
        if self._current_state not in ("DISCONNECTED",):
            self._set_state("DISCONNECTED", "")

    # ---------------------------------------------------------------
    def _set_state(self, state: str, detail: str) -> None:
        self._current_state = state
        color_key, text, sub = STATE_TEXT.get(state, ("busy", state.title(), ""))

        # Shield icon
        self.shield_label.setPixmap(make_shield_pixmap(color_key, 100))

        # Text
        self.status_label.setText(text)
        self.status_label.setStyleSheet(
            f"font-size: 20px; font-weight: 700; "
            f"color: {STATUS_COLORS[color_key]}; background: transparent;"
        )

        # Tray + window icon
        icon = make_shield_icon(color_key)
        self.tray.setIcon(icon)
        self.setWindowIcon(icon)
        self.tray.setToolTip(f"{APP_NAME} — {text}")

        if state == "CONNECTED":
            if self.connected_since is None:
                self.connected_since = time.time()
                if self._has_tray:
                    self.tray.showMessage(APP_NAME, "VPN verbunden.",
                                          QSystemTrayIcon.MessageIcon.Information, 3000)
            self.detail_label.setText(f"IP {detail}" if detail else "")
        elif state == "DISCONNECTED":
            if self.connected_since is not None:
                if self._has_tray:
                    self.tray.showMessage(APP_NAME, "VPN getrennt.",
                                          QSystemTrayIcon.MessageIcon.Information, 3000)
            self.connected_since = None
            self.detail_label.setText("")
        else:
            self.detail_label.setText(sub)

        busy = color_key == "busy"
        connected = state == "CONNECTED"
        is_active = connected or busy
        self.toggle_btn.setEnabled(state != "EXITING")
        self.toggle_btn.setText("Trennen" if is_active else "Verbinden")
        disconnect_style = (
            f"QPushButton#connectBtn {{ background: {THEME['red']}; color: #fff; }}"
            f"QPushButton#connectBtn:hover {{ background: {THEME['red_hover']}; }}"
            f"QPushButton#connectBtn:disabled {{ background: {THEME['surface2']}; color: {THEME['text3']}; }}"
        )
        connect_style = (
            f"QPushButton#connectBtn {{ background: {THEME['accent']}; color: #fff; }}"
            f"QPushButton#connectBtn:hover {{ background: {THEME['accent_hover']}; }}"
            f"QPushButton#connectBtn:disabled {{ background: {THEME['surface2']}; color: {THEME['text3']}; }}"
        )
        self.toggle_btn.setStyleSheet(disconnect_style if is_active else connect_style)
        self.tray_toggle.setText("Trennen" if is_active else "Verbinden")

    def _update_uptime(self) -> None:
        if self.connected_since is None:
            return
        secs = int(time.time() - self.connected_since)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        ip_part = self.detail_label.text().split("·")[0].strip()
        base = ip_part if ip_part.startswith("IP") else ""
        uptime = f"{h:d}:{m:02d}:{s:02d}"
        self.detail_label.setText(f"{base}  ·  {uptime}" if base else uptime)

    def _on_failed(self, message: str) -> None:
        self._set_state("DISCONNECTED", "")
        self.shield_label.setPixmap(make_shield_pixmap("error", 100))
        self.status_label.setText("Fehler")
        self.status_label.setStyleSheet(
            f"font-size: 20px; font-weight: 700; color: {THEME['red']}; background: transparent;"
        )
        self.detail_label.setText("Verbindung fehlgeschlagen")
        self.tray.setIcon(make_shield_icon("error"))
        self.show_window()
        QMessageBox.critical(self, f"{APP_NAME} — Fehler", message)
        self._set_state("DISCONNECTED", "")

    # ---------------------------------------------------------------
    def open_settings(self) -> None:
        dlg = SettingsDialog(self.env, self)
        dlg.token_reset.connect(self._run_wizard)
        dlg.exec()

    def _run_wizard(self) -> None:
        SetupWizard(self.env, self).exec()


# ===================================================================
# main
# ===================================================================
_INSTANCE_SOCK: socket.socket | None = None


def _acquire_instance_lock() -> bool:
    """Bind a local port to prevent running two instances simultaneously."""
    global _INSTANCE_SOCK
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    try:
        s.bind(("127.0.0.1", 19475))
        s.listen(1)
        _INSTANCE_SOCK = s
        return True
    except OSError:
        s.close()
        return False


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    app.setStyleSheet(GLOBAL_STYLE)
    app.setWindowIcon(make_shield_icon("off"))

    if not _acquire_instance_lock():
        QMessageBox.warning(
            None, APP_NAME,
            "HTWG VPN läuft bereits.\nBitte die bestehende Instanz verwenden."
        )
        return 1

    env = EnvStore()

    if not env.is_complete():
        wizard = SetupWizard(env)
        if wizard.exec() != QDialog.DialogCode.Accepted and not env.is_complete():
            return 0

    win = MainWindow(env)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
