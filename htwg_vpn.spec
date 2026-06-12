# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec — HTWG VPN GUI
# Run on each target OS:
#   Windows : pyinstaller htwg_vpn.spec
#   macOS   : pyinstaller htwg_vpn.spec
#   Linux   : pyinstaller htwg_vpn.spec
#
# Output:
#   Windows : dist/htwg-vpn.exe          (~90 MB, single file)
#   macOS   : dist/htwg-vpn.app          (app bundle)
#   Linux   : dist/htwg-vpn             (~90 MB, single file)

import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, BUNDLE, COLLECT

IS_WINDOWS = sys.platform == "win32"
IS_MACOS   = sys.platform == "darwin"
IS_LINUX   = sys.platform.startswith("linux")

a = Analysis(
    ["htwg_vpn.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "dotenv",
        "pyotp",
        "numpy",
        "cv2",
        "PySide6.QtSvg",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras",
        "PySide6.Qt3DInput", "PySide6.Qt3DLogic", "PySide6.Qt3DRender",
        "PySide6.QtAxContainer", "PySide6.QtBluetooth", "PySide6.QtCharts",
        "PySide6.QtDataVisualization", "PySide6.QtDesigner", "PySide6.QtHelp",
        "PySide6.QtLocation", "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
        "PySide6.QtNfc", "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets",
        "PySide6.QtPositioning", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
        "PySide6.QtQuick", "PySide6.QtQuick3D", "PySide6.QtQuickControls2",
        "PySide6.QtQuickWidgets", "PySide6.QtRemoteObjects", "PySide6.QtScxml",
        "PySide6.QtSensors", "PySide6.QtSerialBus", "PySide6.QtSerialPort",
        "PySide6.QtSpatialAudio", "PySide6.QtSql", "PySide6.QtStateMachine",
        "PySide6.QtTest", "PySide6.QtTextToSpeech", "PySide6.QtUiTools",
        "PySide6.QtWebChannel", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineQuick",
        "PySide6.QtWebEngineWidgets", "PySide6.QtWebSockets", "PySide6.QtXml",
        "tkinter", "matplotlib", "scipy", "PIL",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

# ── Windows / Linux — single-file EXE ─────────────────────────────────
if not IS_MACOS:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="htwg-vpn",
        debug=False,
        bootloader_ignore_signals=False,
        strip=IS_LINUX,     # strip debug symbols on Linux to reduce size
        upx=True,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        uac_admin=False,    # app runs as user; only openvpn is elevated
        icon="icon.ico" if (IS_WINDOWS and __import__("os").path.exists("icon.ico")) else None,
    )

# ── macOS — .app bundle ───────────────────────────────────────────────
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="htwg-vpn",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        console=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file="entitlements.plist" if __import__("os").path.exists("entitlements.plist") else None,
        icon="icon.icns" if __import__("os").path.exists("icon.icns") else None,
    )

    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=True,
        upx_exclude=[],
        name="htwg-vpn",
    )

    app = BUNDLE(
        coll,
        name="HTWG VPN.app",
        icon="icon.icns" if __import__("os").path.exists("icon.icns") else None,
        bundle_identifier="de.htwg-konstanz.vpn-gui",
        info_plist={
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
            "NSHighResolutionCapable": True,
            "NSRequiresAquaSystemAppearance": False,  # allow dark mode
            "LSUIElement": False,
        },
    )
