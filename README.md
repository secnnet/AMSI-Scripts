# AMSI Scripts

**PowerShell scripts for AMSI operations.**

### Prerequisites:
- Windows OS
- PowerShell (v5.1+)
- Admin privileges (for some tasks)

### Usage:
1. Clone/download repo.
2. Open PowerShell in script directory.
3. Run desired script:
    - `.\Send-AmsiContent.ps1`: Scan content via AMSI.
    - `.\Get-AMSIEvent.ps1 -Path <trace_path>`: Parse AMSI ETW trace.
    - `.\Get-AMSIScanResult.ps1 -Interactive`: Interactive mode.
    - `.\Get-AMSIScanResult.ps1 -File <input_file_path> -StandardAppName <app_name>`: File mode.

### Notes:
- Run with elevated permissions if needed.
- Understand implications before content scanning.
- Scripts are as-is; use at your own risk.

### Credits:
Scripts modified from Matt Graeber's work at Red Canary. See [Microsoft](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) for AMSI details.

### License:
MIT
