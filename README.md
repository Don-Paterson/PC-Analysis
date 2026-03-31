# PC-Analysis

Comprehensive Windows PC health and inventory assessment.  
Generates a self-contained HTML report covering hardware, storage (SMART), network, security, software, services, event logs, and more.

## Quick Start

Run this one-liner in an **elevated PowerShell session** (right-click PowerShell > Run as Administrator):

```powershell
irm https://raw.githubusercontent.com/Don-Paterson/PC-Analysis/main/run-pc-assessment.ps1 | iex
```

This will:
1. Download `Assess-UserFiles.ps1` to your Desktop
2. Run it immediately with Bypass execution policy
3. Save the HTML report to the same folder the script runs from

## What It Collects

| Section | Details |
|---|---|
| Operating System | Version, build, activation, uptime, BIOS |
| Hardware | CPU, RAM slots/speeds, GPU, monitors, sound |
| Storage & SMART | Physical disk health, reliability counters, logical volumes with usage bars, profile folder sizes, Documents tree |
| Network | Adapters, active TCP connections, listening ports, saved Wi-Fi profiles |
| Security | Defender status, firewall, BitLocker, UAC, pending updates, local users, failed logons |
| Installed Software | Full registry-sourced app list |
| Startup | Registry run keys, startup folder items |
| Services | Running services, stopped auto-start services |
| Scheduled Tasks | Non-Microsoft enabled tasks with command lines |
| Event Logs | Last 24h errors/warnings from System and Application logs |
| Performance | Top 15 processes by CPU and RAM, page file |
| System Integrity | Recent hotfixes, CBS log tail |
| Shares & Remote | SMB shares, RDP status, WinRM |
| Virtualisation | Hyper-V, WSL distributions, Docker containers |
| Browsers | Chrome, Edge, Firefox, Brave, Opera profile detection and size |
| Printers | All printers with port and default status |

## Output

A single self-contained `.html` file saved to the current directory:

```
PC-Assessment-<hostname>-<yyyyMMdd-HHmm>.html
```

Open in any browser. Features:
- Dark theme with fixed sidebar navigation
- Collapsible sections
- Colour-coded health badges (green / amber / red)
- Drive usage fill bars
- SMART disk health and reliability counters

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1+ or pwsh 7.x
- Administrator rights recommended for full output (Security log, BitLocker, Windows Features)

## Files

| File | Purpose |
|---|---|
| `run-pc-assessment.ps1` | Launcher — downloads script to Desktop and runs it |
| `Assess-UserFiles.ps1` | Main assessment script |
