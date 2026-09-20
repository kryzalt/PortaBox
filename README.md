# 📦 PortaBox

[![Release](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://github.com/your-username/PortaBox/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform](https://img.shields.io/badge/Platform-Windows%20(x86%20%7C%20x64)-lightgrey.svg)](#)
[![Donate](https://img.shields.io/badge/Donate-Crypto-f39c12.svg)](#-support--donations)

> **Carry your games and applications anywhere. Leave zero traces on the host PC.**

**PortaBox** is a high-performance, drop-in runtime virtualization and sandbox layer for Windows. By intercepting core filesystem, registry, and network API calls via standard proxy DLLs, PortaBox encapsulates games and standalone software into a self-contained environment. 

Run your favorite titles from external SSDs, USB flash drives, network drives, or devices like the Steam Deck without losing saves, keybindings, or mod configurations.

Compatible with both **classic retro titles** and **modern 64-bit game engines** (Unreal Engine 4/5, Unity, custom runtimes), as well as standalone Windows software.

---

## 🌟 Why PortaBox?

Windows games and applications scatter critical data across your system:
- `%LOCALAPPDATA%`, `%APPDATA%`, and `%USERPROFILE%`
- `Documents\My Games` and `Saved Games`
- `%PROGRAMDATA%`
- Windows Registry (`HKCU\Software\...` / `HKLM\Software\...`)

Reinstalling Windows, playing on another PC, or using a cybercafe PC usually means **losing saves, reconfiguring settings, or leaving private data behind**.

**PortaBox solves this seamlessly without virtual machines or external launchers**

---

## ☕ Support & Donations

PortaBox is a free, open-source project developed and maintained in personal spare time. If PortaBox helped you keep your saves safe, clean up your Windows installation, or run portable game setups from a USB drive, consider buying the developer a coffee!

You can support continued development directly via cryptocurrency:

| Asset | Network | Wallet Address |
| :--- | :--- | :--- |
| **USDT** | TRC-20 | `TBgghhAiMGUbh4Du5JVpzv8zFBv9npugdC` |
| **BTC** | Bitcoin | `bc1q5mvca58yaa2dc49yzhds3n7h28xzg0zjwxss03` |
| **LTC** | Litecoin | `Lhdef5oPpxXFzH1vwxMFhaVZcyacyzJHgF` |
| **ETH** | ERC-20 | `0x58876e3cd3f3a4b3ab4763a68bf9955b6d127c9a` |
| **TON / GRAM** | TON | `UQCwabfDSQXKs0rtzSZXOxknia6RN4t0bOwV5O_P00AIh11h` |

*Thank you for supporting independent open-source software!*

---

## ✨ Key Features

### 🗂️ Transparent Virtual File System (VFS)
- Intercepts and redirects `AppData` (Local, Roaming, LocalLow), `Documents`, `Saved Games`, `ProgramData`, and `%TEMP%` directly into a local `PortableData\` folder.
- Native support for short (8.3) DOS path equivalents.
- **VFS Overlay:** Read-fallback mechanism lets software read essential system assets while saving all modifications locally.

### 🗝️ Virtual Registry Engine
- Virtualizes `HKCU\Software` and `HKLM\Software` into an editable, transparent `registry.ini` file.
- Direct hardware NT API resolution (`NtQueryKey`) eliminates registry clutter and host conflicts.
- Built-in whitelisting ensures system-critical runtimes (DirectX, GPU drivers, Steam/Valve interfaces) talk directly to the host OS without interruption.

### 🛡️ Network Sandbox & Privacy Firewall
- Integrated network isolation engine to block unexpected telemetry, analytics, or background internet traffic.
- Configurable firewall rules: kill WAN traffic while keeping local loopback (`localhost` / `127.0.0.1`) alive for LAN play or local servers.
- Socket call logging for security auditing.

### 🎮 Drop-in DLL Proxy Architecture
- Zero configuration required. Place the compiled DLL next to the executable as:
  - `version.dll`
  - `winmm.dll`
  - `dwmapi.dll`
  - `mscoree.dll`
  - `d3d9.dll`
  - `dxgi.dll`
- Full support for both **32-bit (x86)** and **64-bit (x64)** binaries.

### 🧩 Native ASI Loader & Asset Overload
- **Ultimate ASI Loader** compatible: Automatically discovers and initializes `.asi` plugins from `\`, `\scripts`, `\plugins`, and `\update`.
- **Dynamic File Overload:** Place modified files into an `update\` folder to patch or override game assets on the fly without altering original archives.

### 🚚 Interactive Save Migration Assistant
- Automatically detects existing save data or configuration on the host computer.
- Provides a native UI dialog with a progress bar and countdown timer:
  1. **Start Fresh** (Default — start clean without touching host data)
  2. **Move** (Migrate existing host files to `PortableData\` and remove from system)
  3. **Copy** (Import existing host data into `PortableData\` and keep originals)
  4. **Pass-through** (Use system directory directly)

### 💥 Hardened Crash Protection
- Integrated Vectored Exception Handling (VEH) and Top-Level Filter.
- Creates minidump files (`.dmp`) even under critical conditions like `STACK_OVERFLOW` via dedicated recovery threads.
- Flushes in-memory registry data to disk before emergency termination.

---

## 🚀 Quick Start

1. Download the latest release package from the [Releases](https://github.com/your-username/PortaBox/releases) section.
2. Open the archive and pick the appropriate architecture:
   - `bin_x86\` for 32-bit applications.
   - `bin_x64\` for 64-bit applications.
3. Choose any proxy name (e.g., `version.dll` or `dxgi.dll`) and copy it into the folder where the main game/application executable resides.
4. Launch the application.
5. PortaBox will spin up and create a `PortableData\` folder next to the executable.

---

## ⚙️ Configuration (`portable_config.ini`)

On first launch, `PortableData\portable_config.ini` is generated automatically:

```ini
[General]
EnablePlugins=1         ; 1 = Load .asi plugins automatically
EnableUpdateFolder=1    ; 1 = Enable asset redirection from /update folder
EnableCrashDumps=0      ; 1 = Write minidump files to PortableData/CrashDumps on crash
LogLevel=0              ; 0 = Off, 1 = Errors only, 2 = All I/O trace, 3 = Network only

[Network]
EnableNetwork=1         ; Master toggle for network hooking engine
BlockInternet=0         ; 1 = Block all outbound Internet traffic
LogNetwork=0            ; 1 = Log socket connection attempts to portable_debug.log
AllowLocalhost=1        ; 1 = Keep loopback connections (127.0.0.1) accessible

[FileMigration]
; Stores migration decisions for detected file locations

[RegMigration]
; Stores migration decisions for detected registry paths
```
## 🛠️ Building from Source

### Requirements
- Microsoft Visual Studio 2022 (Community, Professional, or Build Tools) with **Desktop development with C++** installed.
- Windows SDK.

### Build Script
Open a command prompt in the project root and run:

```bat
build.bat
```
The script will locate your Visual Studio compiler environment, build both x86 and x64 targets, and output ready-to-use DLLs into bin_x86\ and bin_x64\.

## 📄 License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**. See the [LICENSE](LICENSE) file for details.

*PortaBox is developed for software preservation, privacy, and backup purposes.*
