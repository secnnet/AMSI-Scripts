# AMSI Script Collection

This repository contains a collection of PowerShell scripts related to the Antimalware Scan Interface (AMSI). The scripts provide functionality for interacting with AMSI, scanning content, and retrieving AMSI event information.

## Prerequisites

- Windows operating system
- PowerShell (version 5.1 or later)
- Administrative privileges (required for some operations)

## Usage

1. Clone or download this repository to your local machine.

2. Open a PowerShell session and navigate to the directory where the scripts are located.

3. Run the desired script using the following steps:

    - **Send-AmsiContent**: This script allows you to pass content buffers to be scanned by an AMSI provider using the AmsiScanBuffer function. Modify the script according to your specific needs, ensuring you have created an antivirus exception for this script to prevent triggering AV engine signatures. To run the script, execute the following command:
    
      ```powershell
      .\Send-AmsiContent.ps1
      ```

    - **Get-AMSIEvent**: This script parses an AMSI Event Tracing for Windows (ETW) trace file and retrieves information about AMSI events. To use this script, provide the path to the trace file as the `-Path` parameter. For example:
    
      ```powershell
      .\Get-AMSIEvent.ps1 -Path C:\Path\To\AMSI\Trace.etl
      ```

    - **Get-AMSIScanResult**: This script starts an AMSI ETW trace, collects AMSI events, and prints them to the console. It provides two execution modes:
    
      - Interactive mode: It waits for the user to trigger AMSI detections and awaits an Enter keypress. When Enter is pressed, it pulls the collected AMSI events. To run in interactive mode, execute the following command:
      
        ```powershell
        .\Get-AMSIScanResult.ps1 -Interactive
        ```
      
      - File mode: It scans an input file specified by the `-File` parameter and collects AMSI events related to the scan. Provide the path to the input file and optionally specify the `-StandardAppName` parameter to emulate a specific application name. To run in file mode, execute the following command:
      
        ```powershell
        .\Get-AMSIScanResult.ps1 -File C:\Path\To\Input\File.txt -StandardAppName PowerShell
        ```

## Notes

- Some operations in these scripts require administrative privileges. Ensure that you run the scripts with an elevated PowerShell session.
- Take caution when running scripts that involve content scanning. Make sure you understand the implications and have necessary AV exceptions in place to prevent false positives.
- These scripts are provided as-is, without any warranty. Use them at your own risk.

## Credits

- The `Send-AmsiContent` and `Get-AMSIEvent` functions were authored by Matt Graeber from Red Canary. They have been modified and included in this repository for convenience.

For more information about AMSI, refer to the [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal).

For any issues or suggestions, please open an issue in this repository.

## License

This project is licensed under the [MIT License](LICENSE).

