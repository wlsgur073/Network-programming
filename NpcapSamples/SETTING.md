# Network Programming Project Setup

## Development Environment
- **OS**: Windows 11
- **IDE**: Visual Studio 2022 Community
- **Network Tools**: WireShark x64 4.4.3 + Npcap 1.78 | [wireshark.org](https://www.wireshark.org/download.html)
- **SDK**: Npcap SDK 1.13 | [npcap.com](https://npcap.com/#download)
- **Virtualization**: VMware Player 17 (for Windows 11 VM) | [techspot.com](https://www.techspot.com/downloads/1969-vmware-player.html)

> **Note**: Make sure to enable the virtualization technology (VT-x/AMD-V) in the BIOS of your motherboard.

---

## Visual Studio Project Configuration

### 1. VC++ Directory Configuration
- **External Include Directories**: `C:\npcap\Include`
- **Library Directories**: `C:\npcap\Lib\x64`

### 2. Linker Configuration
- **Path**: Project Properties > Linker > Input > Delay Loaded DLLs
- **Add**: `wpcap.dll`

> **Description**:  
> Using the delay-loaded DLL configuration allows the DLL (`wpcap.dll`) to be loaded when its functions are called during runtime.  
> This prevents potential loading errors of `wpcap.dll`.

---

## Trace File Setup

- **Download Trace Files**: [Chappell University](https://www.chappell-university.com/traces)  
- **Save Trace Files to**: `C:\SampleTraces`

---

## Visual Studio Development Environment Initialization

1. Go to **Tools** > **Import and Export Settings**
2. Select **Reset all settings**
3. Set it to **Visual C++**

---

Use this guide to set up your network programming environment and start developing your project seamlessly.
