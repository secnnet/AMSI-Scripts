function Send-AmsiContent {
    [CmdletBinding(DefaultParameterSetName = 'CustomAppNameByteContent')]
    param (
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'StandardAppNameStringContent')]
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'StandardAppNameByteContent')]
        [String]
        [ValidateSet('PowerShell', 'VBScript', 'JScript', 'WMI', 'DotNet', 'coreclr', 'VSS', 'Excel', 'Excel.exe', 'OFFICE_VBA', 'Exchange Server 2016')]
        $StandardAppName,

        [Parameter(Mandatory, Position = 0, ParameterSetName = 'CustomAppNameStringContent')]
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'CustomAppNameByteContent', ValueFromPipelineByPropertyName)]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('AppName')]
        $CustomAppName,

        [Parameter(Mandatory, Position = 1, ParameterSetName = 'StandardAppNameByteContent')]
        [Parameter(Mandatory, Position = 1, ParameterSetName = 'CustomAppNameByteContent', ValueFromPipelineByPropertyName)]
        [Byte[]]
        [Alias('Content')]
        $ContentBytes,

        [Parameter(Mandatory, Position = 1, ParameterSetName = 'StandardAppNameStringContent')]
        [Parameter(Mandatory, Position = 1, ParameterSetName = 'CustomAppNameStringContent')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ContentString,

        [Parameter(Position = 2, ValueFromPipelineByPropertyName)]
        [String]
        $ContentName
    )

    # Load AMSI functions from amsi.dll using P/Invoke
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;

        public static class AmsiNativeMethods {
            public enum AMSI_RESULT {
                AMSI_RESULT_CLEAN = 0,
                AMSI_RESULT_NOT_DETECTED = 1,
                AMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN = 0x4000,
                AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4fff,
                AMSI_RESULT_DETECTED = 32768,
            }

            [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall)]
            public static extern int AmsiInitialize(string appName, ref IntPtr amsiContext);

            [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall)]
            public static extern void AmsiUninitialize(IntPtr amsiContext);

            [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall)]
            public static extern int AmsiOpenSession(IntPtr amsiContext, ref IntPtr amsiSession);

            [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall)]
            public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr amsiSession);

            [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall)]
            public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr amsiSession, ref AMSI_RESULT result);
        }
"@

    # Determine the application name based on the parameter values
    if ($CustomAppName) {
        $FullAppName = $CustomAppName
    } else {
        switch ($StandardAppName) {
            'PowerShell' {
                # Emulate the dynamically built app name used by PowerShell
                $PowerShellProcess = Get-Process -Id $PID
                $FullAppName = "PowerShell_$($PowerShellProcess.Path)_$($PSVersionTable.BuildVersion.ToString())"
            }
            'DotNet', 'coreclr', 'VSS' {
                Write-Warning "$StandardAppName content is expected to be supplied as a byte array but string content was provided."
                $FullAppName = $StandardAppName
            }
            default {
                $FullAppName = $StandardAppName
            }
        }
    }

    # Determine the content name
    $ContentNameString = $ContentName ?? ''

    # Determine the content data
    if ($ContentBytes) {
        $Content = $ContentBytes
    } else {
        $Content = [Text.Encoding]::Unicode.GetBytes($ContentString)
    }

    $AmsiContext = [IntPtr]::Zero
    $AmsiSession = [IntPtr]::Zero
    $AmsiResult = [AmsiNativeMethods+AMSI_RESULT]::AMSI_RESULT_CLEAN

    # Initialize AMSI context
    $Result = [AmsiNativeMethods]::AmsiInitialize($FullAppName, [ref] $AmsiContext)
    if ($Result -ne 0) {
        $Failure = [ComponentModel.Win32Exception] $Result
        Write-Error -Message "AmsiInitialize failed. Message: $($Failure.Message). Error code: $($Failure.NativeErrorCode)"
    }

    # Open an AMSI session
    $Result = [AmsiNativeMethods]::AmsiOpenSession($AmsiContext, [ref] $AmsiSession)
    if ($Result -ne 0) {
        [AmsiNativeMethods]::AmsiUninitialize($AmsiContext)
        $Failure = [ComponentModel.Win32Exception] $Result
        Write-Error -Message "AmsiOpenSession failed. Message: $($Failure.Message). Error code: $($Failure.NativeErrorCode)"
    }

    # Scan the content buffer
    $Result = [AmsiNativeMethods]::AmsiScanBuffer($AmsiContext, $Content, $Content.Length, $ContentNameString, $AmsiSession, [ref] $AmsiResult)
    if ($Result -ne 0) {
        $Failure = [ComponentModel.Win32Exception] $Result
        Write-Error -Message "AmsiScanBuffer failed. Message: $($Failure.Message). Error code: $($Failure.NativeErrorCode)"
    }

    # Close the AMSI session and clean up
    [AmsiNativeMethods]::AmsiCloseSession($AmsiContext, $AmsiSession)
    [AmsiNativeMethods]::AmsiUninitialize($AmsiContext)
}


# Function: Get-AMSIEvent
# Author: Matt Graeber
# Company: Red Canary
# Description: Parses the contents of an AMSI ETW trace file and retrieves AMSI event information.

function Get-AMSIEvent {
    param (
        [Parameter(Mandatory)]
        [String]
        [ValidatePattern('\.etl$')] # Ensure the file path ends with .etl
        $Path,

        [Switch]
        $AsByteArray
    )

    # Filter and retrieve AMSI events from the ETW trace file
    $AMSIEvents = Get-WinEvent -Path $Path -Oldest -FilterXPath 'Event[System[Provider[@Name="Microsoft-Antimalware-Scan-Interface"]] and System[EventID=1101]]'

    foreach ($Event in $AMSIEvents) {
        $ScanResultValue = $Event.Properties[2].Value

        # Map scan result values to human-readable strings
        $ScanResult = switch ($ScanResultValue) {
            0                        { 'AMSI_RESULT_CLEAN' }
            1                        { 'AMSI_RESULT_NOT_DETECTED' }
            32768                    { 'AMSI_RESULT_DETECTED' }
            { $_ -ge 0x4000 -and $_ -le 0x4FFF }   { 'AMSI_RESULT_BLOCKED_BY_ADMIN' }
            default                  { $ScanResultValue }
        }

        $AppName = $Event.Properties[3].Value

        if ($AsByteArray) {
            $AMSIContent = $Event.Properties[7].Value
        } else {
            if ($AppName -eq 'DotNet') {
                # Convert the AMSI buffer (PE file) to a byte array
                $AMSIContent = [BitConverter]::ToString($Event.Properties[7].Value) -replace '-'
            } else {
                # Convert the AMSI buffer (unicode-encoded script code) to a string
                $AMSIContent = [Text.Encoding]::Unicode.GetString($Event.Properties[7].Value)
            }
        }

        # Create a custom object with AMSI event properties
        [PSCustomObject] @{
            ProcessId     = $Event.ProcessId
            ThreadId      = $Event.ThreadId
            TimeCreated   = $Event.TimeCreated
            Session       = $Event.Properties[0].Value
            ScanStatus    = $Event.Properties[1].Value
            ScanResult    = $ScanResult
            AppName       = $AppName
            ContentName   = $Event.Properties[4].Value
            ContentSize   = $Event.Properties[5].Value
            OriginalSize  = $Event.Properties[6].Value
            Content       = $AMSIContent
            Hash          = ($Event.Properties[8].Value | ForEach-Object { '{0:X2}' -f $_ }) -join ''
            ContentFiltered = $Event.Properties[9].Value
        }
    }
}
