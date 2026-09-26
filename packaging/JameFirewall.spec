# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

datas_tb, binaries_tb, hidden_tb = collect_all('ttkbootstrap')

a = Analysis(
    ['../src/jame_firewall/__main__.py'],
    pathex=['../src'],
    binaries=binaries_tb,
    datas=[
        ('../res/icon/128.ico', 'res/icon'),
        ('../res/icon/32.ico', 'res/icon'),
    ] + datas_tb,
    hiddenimports=[
        'ttkbootstrap',
        'PIL.ImageTk',
        'tkinter',
        'winreg',
    ] + hidden_tb,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter.test',
        'test',
        'unittest',
        'doctest',
        'pydoc',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
    optimize=2,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='JameFirewall',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['../res/icon/128.ico'],
)
