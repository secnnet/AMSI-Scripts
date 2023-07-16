#Requires -RunAsAdministrator

function Get-AMSIScanResult {
    param (
        [string]
        $File = "",

        [string]
        $StandardAppName = "OFFICE_VBA",

        [switch]
        $Interactive,

        [string]
        $TraceFile = "AMSITrace.etl"
    )

    # Check if either File or Interactive parameter is specified
    if (-not $Interactive -and $File -eq "") {
        Write-Error "You must specify -File or -Interactive."
    }

    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    # Step 1: Disable AMSI for this PowerShell runspace
    [Runtime.InteropServices.Marshal]::WriteByte((([Ref].Assembly.GetTypes() | Where-Object { $_ -clike '*Am*ls' }).GetFields(40) | Where-Object { $_ -clike '*xt' }).GetValue($null), 0x5)

    # Step 2: Load Matt Graeber's AMSITools.ps1
    . "$PSScriptRoot\AMSITools.ps1"

    # Step 3: Start an ETW Trace
    Remove-Item $TraceFile -ErrorAction SilentlyContinue | Out-Null
    logman start AMSITrace -p Microsoft-Antimalware-Scan-Interface Event1 -o $TraceFile -ets | Out-Null

    if ($Interactive) {
        Write-Host "Trigger AMSI detections now and then press any key to pull AMSI events..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    } else {
        # Step 4: Read input file
        $bytes = Get-Content $File -Encoding Byte

        # Step 5: Feed AMSI trace
        Send-AmsiContent -StandardAppName $StandardAppName -ContentBytes $bytes
    }

    # Step 6: Stop ETW Trace
    logman stop AMSITrace -ets | Out-Null

    # Step 7: Pull collected events
    Get-AMSIEvent -Path $TraceFile

    Write-Host "If you wish to pull AMSI events again, simply run in this terminal:`n`tGet-AMSIEvent -Path $TraceFile`n"
}
