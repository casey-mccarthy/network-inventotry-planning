<#
.SYNOPSIS
    Validates Active Directory environment readiness for Inventory Agent deployment.

.DESCRIPTION
    Comprehensive pre-deployment validation script that checks for security controls,
    permissions, and configurations that could block inventory agent deployment.

    This script is designed for government/enterprise environments where multiple
    security controls may interfere with agent deployment:
    - AppLocker/WDAC policies
    - Constrained Language Mode
    - Execution policies
    - WMI/CIM permissions
    - Network segmentation
    - Certificate requirements
    - EDR/antivirus interference

    TEST CATEGORIES:
    1. PowerShell Environment (version, execution policy, language mode, privileges)
    2. Application Control (AppLocker, WDAC policies)
    3. WMI/CIM Access (permissions for system information queries)
    4. Event Log Access (read/write permissions)
    5. Network Connectivity (DNS, TCP, HTTPS to server)
    6. Certificate Store Access (client certificates)
    7. Security Software (Windows Defender, EDR detection)
    8. File System Access (directory creation, write permissions)
    9. Scheduled Task Capability (service status, task creation)

    OUTPUT:
    - Color-coded console output (green/yellow/red)
    - Pass/Warn/Fail status for each check
    - Remediation guidance for failures
    - Optional JSON export for documentation

    USAGE SCENARIOS:
    - Pre-deployment validation (run before mass deployment)
    - Troubleshooting failed deployments
    - Security compliance documentation
    - Audit trail for change control

.PARAMETER ServerEndpoint
    [string] The inventory server endpoint to test connectivity.
    Default: "https://inventory.company.com"

    Used for DNS resolution, TCP connectivity, and HTTPS validation tests.

.PARAMETER Detailed
    [switch] Show detailed output for all checks including remediation steps.
    Default: $false

    When specified, displays:
    - Detailed remediation instructions
    - Additional technical details
    - Full error messages

.PARAMETER ExportReport
    [switch] Export test results to JSON file.
    Default: $false

    Creates JSON report for:
    - Change control documentation
    - Management reporting
    - Historical tracking

.PARAMETER ReportPath
    [string] Path for JSON report file.
    Default: ".\DeploymentReadinessReport.json"

    Only used if -ExportReport is specified.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Int32
    Exit code 0 if environment is ready (no critical issues)
    Exit code 1 if critical issues found

    Side effects:
    - Console output with color-coded results
    - Optional JSON report file

.EXAMPLE
    PS> .\Test-DeploymentReadiness.ps1

    Runs all checks with default server endpoint and summary output.

.EXAMPLE
    PS> .\Test-DeploymentReadiness.ps1 -ServerEndpoint "https://inventory.company.com" -Detailed

    Runs all checks with detailed remediation guidance.

.EXAMPLE
    PS> .\Test-DeploymentReadiness.ps1 -ExportReport -ReportPath "C:\Reports\ReadinessCheck.json"

    Runs checks and exports results to JSON file.

.EXAMPLE
    PS> .\Test-DeploymentReadiness.ps1 -Detailed | Tee-Object -FilePath "readiness.log"

    Runs checks with detailed output and saves to log file.

.NOTES
    File Name      : Test-DeploymentReadiness.ps1
    Version        : 1.0.0
    Author         : IT Operations Team
    Prerequisite   : PowerShell 5.1 or higher
    Prerequisite   : Run on target workstation (not remotely)

    GOVERNMENT/ENTERPRISE CONSIDERATIONS:
    - Designed for high-security environments
    - Detects STIG/CIS hardening controls
    - Identifies air-gapped network configurations
    - Tests for PKI/certificate requirements
    - Validates EDR/AV compatibility

    INTERPRETING RESULTS:
    - PASS (✓): Check passed, no issues
    - WARN (⚠): Non-critical issue, may impact functionality
    - FAIL (✗): Critical issue, must be resolved before deployment

    COMMON ISSUES:
    - AppLocker/WDAC blocking PowerShell execution
    - Constrained Language Mode restricting functionality
    - Firewall blocking outbound HTTPS
    - Missing WMI permissions
    - Certificate store access denied

.LINK
    https://docs.company.com/inventory-agent/deployment-readiness

.LINK
    https://docs.company.com/inventory-agent/troubleshooting
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false,
               Position = 0,
               HelpMessage = "Inventory server endpoint to test connectivity")]
    [ValidateNotNullOrEmpty()]
    [string]$ServerEndpoint = "https://inventory.company.com",

    [Parameter(Mandatory = $false,
               HelpMessage = "Show detailed output including remediation steps")]
    [switch]$Detailed,

    [Parameter(Mandatory = $false,
               HelpMessage = "Export test results to JSON file")]
    [switch]$ExportReport,

    [Parameter(Mandatory = $false,
               HelpMessage = "Path for JSON report export")]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath = ".\DeploymentReadinessReport.json"
)

#region Script-Level Variables
<#
    SCRIPT CONFIGURATION
    Global variables for test results tracking and output formatting.
#>

# Color codes for console output (ANSI-style)
# Used for Pass/Warn/Fail status visualization
[hashtable]$script:Colors = @{
    Pass    = "Green"       # ✓ Success
    Fail    = "Red"         # ✗ Critical failure
    Warning = "Yellow"      # ⚠ Non-critical warning
    Info    = "Cyan"        # ● Informational
    Header  = "Magenta"     # Section headers
}

# Test results collection
# Populated throughout script execution for summary and reporting
[hashtable]$script:Results = @{
    TestDate       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName   = $env:COMPUTERNAME
    Checks         = @()               # Array of individual check results
    OverallStatus  = "Unknown"         # READY, READY_WITH_WARNINGS, NOT_READY
    CriticalIssues = 0                 # Count of FAIL results
    Warnings       = 0                 # Count of WARN results
    Passed         = 0                 # Count of PASS results
}
#endregion

#region Output Functions
<#
    CONSOLE OUTPUT FUNCTIONS
    Formatted output for test results with color-coding and structure.
#>

function Write-TestHeader {
    <#
    .SYNOPSIS
        Writes formatted section header to console.

    .DESCRIPTION
        Outputs section header with consistent formatting and color.
        Used to visually separate different test categories.

    .PARAMETER Title
        [string] Section title to display.

    .INPUTS
        None.

    .OUTPUTS
        None. Writes to console as side effect.

    .EXAMPLE
        Write-TestHeader "PowerShell Environment Checks"

        Displays formatted header in magenta.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Title
    )

    Write-Host "`n========================================" -ForegroundColor $Colors.Header
    Write-Host $Title -ForegroundColor $Colors.Header
    Write-Host "========================================" -ForegroundColor $Colors.Header
}

function Write-TestResult {
    <#
    .SYNOPSIS
        Records and displays individual test result.

    .DESCRIPTION
        Formats and outputs test result to console, and adds result to
        global results collection for summary and reporting.

        RESULT FORMAT:
        [Symbol] Test Name : Message
        Where symbol is:
        - ✓ (green) for PASS
        - ⚠ (yellow) for WARN
        - ✗ (red) for FAIL
        - ● (cyan) for INFO

    .PARAMETER TestName
        [string] Name of the test being performed.

    .PARAMETER Status
        [string] Test result status.
        Valid values: "PASS", "WARN", "FAIL", "INFO"

    .PARAMETER Message
        [string] Result message describing the outcome.

    .PARAMETER Remediation
        [string] Remediation guidance for failures/warnings.
        Optional. Only displayed in -Detailed mode.

    .PARAMETER Details
        [object] Additional technical details (hashtable, array, etc.)
        Optional. Only displayed in -Detailed mode.

    .INPUTS
        None.

    .OUTPUTS
        None. Updates $script:Results and writes to console.

    .EXAMPLE
        Write-TestResult -TestName "PowerShell Version" `
                         -Status "PASS" `
                         -Message "Version 5.1 is supported" `
                         -Details @{Version="5.1.19041.4648"}

        Records passing test with details.

    .EXAMPLE
        Write-TestResult -TestName "WMI Access" `
                         -Status "FAIL" `
                         -Message "Access denied" `
                         -Remediation "Run as administrator"

        Records failing test with remediation guidance.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TestName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "FAIL", "WARN", "INFO")]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Remediation = "",

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Details = $null
    )

    # Build result object for collection
    [hashtable]$Result = @{
        TestName    = $TestName
        Status      = $Status
        Message     = $Message
        Remediation = $Remediation
        Details     = $Details
    }

    # Add to results collection
    $script:Results.Checks += $Result

    # Determine color and update counters based on status
    [string]$StatusColor = switch ($Status) {
        "PASS" { $Colors.Pass; $script:Results.Passed++ }
        "FAIL" { $Colors.Fail; $script:Results.CriticalIssues++ }
        "WARN" { $Colors.Warning; $script:Results.Warnings++ }
        default { $Colors.Info }
    }

    # Select status symbol
    [string]$StatusSymbol = switch ($Status) {
        "PASS" { "✓" }
        "FAIL" { "✗" }
        "WARN" { "⚠" }
        default { "●" }
    }

    # Output main result line
    Write-Host "  $StatusSymbol " -ForegroundColor $StatusColor -NoNewline
    Write-Host "$TestName : " -NoNewline
    Write-Host $Message -ForegroundColor $StatusColor

    # Output remediation if in detailed mode and remediation exists
    if ($Detailed -and $Remediation) {
        Write-Host "    Remediation: $Remediation" -ForegroundColor Yellow
    }

    # Output details if in detailed mode and details exist
    if ($Detailed -and $Details) {
        Write-Host "    Details: $($Details | ConvertTo-Json -Compress)" -ForegroundColor Gray
    }
}
#endregion

#region PowerShell Environment Checks
function Test-PowerShellEnvironment {
    <#
    .SYNOPSIS
        Validates PowerShell environment configuration.

    .DESCRIPTION
        Checks PowerShell version, execution policy, language mode, and
        privilege level. These are foundational requirements for agent operation.

        CHECKS PERFORMED:
        1. PowerShell Version (requires 5.1 or higher)
        2. Execution Policy (should not be Restricted)
        3. Language Mode (detects Constrained Language Mode)
        4. Administrator Rights (required for installation)

        LANGUAGE MODE IMPACT:
        - FullLanguage: All features available
        - ConstrainedLanguage: Restricts .NET access, Add-Type, etc.
          Agent is compatible but some features disabled (compression)

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - This function should be called first (foundational checks)
        - Constrained Language Mode is enforced by AppLocker/Device Guard
        - Execution policy can be set via GPO or locally
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "PowerShell Environment Checks"

    # === CHECK 1: POWERSHELL VERSION ===
    # Minimum requirement: PowerShell 5.1
    # Reason: CIM cmdlets, improved remoting, JSON support
    [version]$PSVersion = $PSVersionTable.PSVersion

    if ($PSVersion.Major -ge 5 -and $PSVersion.Minor -ge 1) {
        Write-TestResult -TestName "PowerShell Version" `
                         -Status "PASS" `
                         -Message "Version $($PSVersion.ToString()) is supported" `
                         -Details @{Version=$PSVersion.ToString()}
    }
    else {
        Write-TestResult -TestName "PowerShell Version" `
                         -Status "FAIL" `
                         -Message "Version $($PSVersion.ToString()) is too old" `
                         -Remediation "Upgrade to PowerShell 5.1 or higher via Windows Management Framework" `
                         -Details @{Version=$PSVersion.ToString()}
    }

    # === CHECK 2: EXECUTION POLICY ===
    # Determines if scripts can execute
    # Policy hierarchy: MachinePolicy > UserPolicy > Process > CurrentUser > LocalMachine
    [string]$ExecutionPolicy = Get-ExecutionPolicy -Scope LocalMachine

    # Evaluate policy status
    # Restricted: No scripts allowed (FAIL)
    # Undefined: No policy set (WARN - may inherit restrictive policy)
    # Bypass/Unrestricted: All scripts allowed (PASS)
    # RemoteSigned: Requires signature for remote scripts (PASS)
    # AllSigned: Requires signature for all scripts (WARN - must sign agent scripts)
    [string]$PolicyStatus = switch ($ExecutionPolicy) {
        "Restricted"    { "FAIL" }
        "Undefined"     { "WARN" }
        "Bypass"        { "PASS" }
        "RemoteSigned"  { "PASS" }
        "AllSigned"     { "WARN" }
        "Unrestricted"  { "PASS" }
        default         { "WARN" }
    }

    [string]$PolicyMessage = "Current policy: $ExecutionPolicy"
    [string]$PolicyRemediation = if ($ExecutionPolicy -eq "Restricted") {
        "Set execution policy via GPO: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
    }
    elseif ($ExecutionPolicy -eq "AllSigned") {
        "Ensure all scripts are digitally signed, or change policy to RemoteSigned"
    }
    else { "" }

    Write-TestResult -TestName "Execution Policy" `
                     -Status $PolicyStatus `
                     -Message $PolicyMessage `
                     -Remediation $PolicyRemediation `
                     -Details @{Policy=$ExecutionPolicy; Scope="LocalMachine"}

    # === CHECK 3: LANGUAGE MODE ===
    # Detects PowerShell language restrictions
    # FullLanguage: No restrictions (normal)
    # ConstrainedLanguage: Restricted by AppLocker/WDAC (limited .NET access)
    [string]$LanguageMode = $ExecutionContext.SessionState.LanguageMode

    if ($LanguageMode -eq "ConstrainedLanguage") {
        Write-TestResult -TestName "Language Mode" `
                         -Status "WARN" `
                         -Message "Constrained Language Mode detected" `
                         -Remediation "Agent is compatible but compression features will be disabled" `
                         -Details @{Mode=$LanguageMode}
    }
    elseif ($LanguageMode -eq "FullLanguage") {
        Write-TestResult -TestName "Language Mode" `
                         -Status "PASS" `
                         -Message "Full Language Mode available" `
                         -Details @{Mode=$LanguageMode}
    }
    else {
        Write-TestResult -TestName "Language Mode" `
                         -Status "WARN" `
                         -Message "Unexpected Language Mode: $LanguageMode" `
                         -Details @{Mode=$LanguageMode}
    }

    # === CHECK 4: ADMINISTRATOR RIGHTS ===
    # Required for: scheduled task creation, event log source creation, WMI access
    [bool]$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($IsAdmin) {
        Write-TestResult -TestName "Administrator Rights" `
                         -Status "PASS" `
                         -Message "Running with administrator privileges" `
                         -Details @{IsAdmin=$IsAdmin}
    }
    else {
        Write-TestResult -TestName "Administrator Rights" `
                         -Status "WARN" `
                         -Message "Not running as administrator (required for installation)" `
                         -Remediation "Run as administrator to install scheduled tasks and create event log source" `
                         -Details @{IsAdmin=$IsAdmin}
    }
}
#endregion

#region Application Control Checks
function Test-ApplicationControl {
    <#
    .SYNOPSIS
        Checks for application control policies (AppLocker/WDAC).

    .DESCRIPTION
        Detects AppLocker and WDAC policies that may block script execution.

        APPLOCKER:
        - Rule-based application whitelisting
        - Can block PowerShell scripts by path or publisher
        - Common in enterprise environments

        WDAC (Windows Defender Application Control):
        - More secure than AppLocker
        - Code integrity enforcement at kernel level
        - Common in government/high-security environments

        IMPACT:
        Both can block inventory agent execution unless rules are created.

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - AppLocker rules can be queried via Get-AppLockerPolicy
        - WDAC policies queried via WMI (root\Microsoft\Windows\CI)
        - Presence of policies doesn't guarantee blocking (depends on rules)
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "Application Control Checks"

    # === CHECK 1: APPLOCKER POLICY ===
    try {
        [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]$AppLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop

        if ($AppLockerPolicy) {
            # Count total rules across all collections
            [int]$RuleCount = 0
            foreach ($RuleCollection in $AppLockerPolicy.RuleCollections) {
                $RuleCount += $RuleCollection.Count
            }

            if ($RuleCount -gt 0) {
                Write-TestResult -TestName "AppLocker Policy" `
                                 -Status "WARN" `
                                 -Message "AppLocker is active with $RuleCount rules" `
                                 -Remediation "Create AppLocker rules to allow C:\ProgramData\InventoryAgent\* and PowerShell.exe" `
                                 -Details @{RuleCount=$RuleCount; Collections=$AppLockerPolicy.RuleCollections.Count}

                # Check for PowerShell-specific script rules
                $PSRules = $AppLockerPolicy.RuleCollections | Where-Object { $_.RuleCollectionType -eq "Script" }
                if ($PSRules -and $PSRules.Count -gt 0) {
                    Write-TestResult -TestName "AppLocker Script Rules" `
                                     -Status "WARN" `
                                     -Message "PowerShell script rules detected ($($PSRules.Count) rules)" `
                                     -Remediation "Ensure inventory scripts are allowed by publisher or path rule" `
                                     -Details @{ScriptRules=$PSRules.Count}
                }
            }
            else {
                Write-TestResult -TestName "AppLocker Policy" `
                                 -Status "PASS" `
                                 -Message "AppLocker policy exists but no rules configured" `
                                 -Details @{RuleCount=0}
            }
        }
        else {
            Write-TestResult -TestName "AppLocker Policy" `
                             -Status "PASS" `
                             -Message "No AppLocker policy detected" `
                             -Details @{Configured=$false}
        }
    }
    catch {
        Write-TestResult -TestName "AppLocker Policy" `
                         -Status "INFO" `
                         -Message "Unable to query AppLocker status (may not be configured)" `
                         -Details @{Error=$_.Exception.Message}
    }

    # === CHECK 2: WDAC (WINDOWS DEFENDER APPLICATION CONTROL) ===
    # WDAC is the successor to Device Guard Code Integrity
    # Enforced at kernel level (more secure than AppLocker)
    try {
        [Microsoft.Management.Infrastructure.CimInstance[]]$CIPolicy = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CIPolicyInfo -ErrorAction Stop

        if ($CIPolicy) {
            Write-TestResult -TestName "WDAC Policy" `
                             -Status "WARN" `
                             -Message "Windows Defender Application Control is active" `
                             -Remediation "Create WDAC allow rules for inventory agent scripts and PowerShell" `
                             -Details @{PolicyCount=$CIPolicy.Count}
        }
        else {
            Write-TestResult -TestName "WDAC Policy" `
                             -Status "PASS" `
                             -Message "No WDAC policy detected" `
                             -Details @{Configured=$false}
        }
    }
    catch {
        Write-TestResult -TestName "WDAC Policy" `
                         -Status "PASS" `
                         -Message "WDAC not configured or not supported" `
                         -Details @{Configured=$false}
    }
}
#endregion

#region WMI/CIM Access Checks
function Test-WMIAccess {
    <#
    .SYNOPSIS
        Validates WMI/CIM access for inventory collection.

    .DESCRIPTION
        Tests access to WMI classes required for hardware inventory.
        The agent relies heavily on WMI queries for system information.

        CRITICAL WMI CLASSES TESTED:
        - Win32_BIOS: System serial number (primary asset identifier)
        - Win32_ComputerSystem: Computer name, domain, manufacturer
        - Win32_OperatingSystem: OS version, boot time
        - Win32_Processor: CPU information
        - Win32_DiskDrive: Disk serial numbers
        - Win32_NetworkAdapterConfiguration: Network configuration

        WMI ACCESS REQUIREMENTS:
        - DCOM permissions
        - WMI namespace permissions
        - Local administrator (for full access)
        - WMI service running

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - Uses Get-CimInstance (not Get-WmiObject)
        - CIM uses WS-MAN protocol (more secure than DCOM)
        - Running as SYSTEM (scheduled task) has full WMI access
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "WMI/CIM Access Checks"

    # Define WMI classes to test
    # Each class includes: class name, required flag, description
    [hashtable[]]$WMIClasses = @(
        @{Class="Win32_BIOS"; Required=$true; Description="System serial number and BIOS info"},
        @{Class="Win32_ComputerSystem"; Required=$true; Description="Computer name, domain, manufacturer"},
        @{Class="Win32_OperatingSystem"; Required=$true; Description="OS version and boot time"},
        @{Class="Win32_Processor"; Required=$true; Description="CPU information"},
        @{Class="Win32_DiskDrive"; Required=$true; Description="Disk serial numbers"},
        @{Class="Win32_NetworkAdapterConfiguration"; Required=$true; Description="Network adapter info"}
    )

    # Test each WMI class
    foreach ($WMITest in $WMIClasses) {
        try {
            # Query WMI class (limit to 1 result for speed)
            [Microsoft.Management.Infrastructure.CimInstance]$Result = Get-CimInstance -ClassName $WMITest.Class -ErrorAction Stop | Select-Object -First 1

            if ($Result) {
                Write-TestResult -TestName "WMI: $($WMITest.Class)" `
                                 -Status "PASS" `
                                 -Message "Successfully queried $($WMITest.Description)" `
                                 -Details @{Class=$WMITest.Class}
            }
            else {
                Write-TestResult -TestName "WMI: $($WMITest.Class)" `
                                 -Status "WARN" `
                                 -Message "Query succeeded but returned no data" `
                                 -Details @{Class=$WMITest.Class}
            }
        }
        catch {
            # Determine severity based on required flag
            [string]$Status = if ($WMITest.Required) { "FAIL" } else { "WARN" }

            Write-TestResult -TestName "WMI: $($WMITest.Class)" `
                             -Status $Status `
                             -Message "Access denied or query failed" `
                             -Remediation "Verify WMI service is running and user has WMI permissions" `
                             -Details @{Class=$WMITest.Class; Error=$_.Exception.Message}
        }
    }
}
#endregion

#region Event Log Access Checks
function Test-EventLogAccess {
    <#
    .SYNOPSIS
        Tests Event Log read/write permissions.

    .DESCRIPTION
        Validates access to Windows Event Logs for agent logging.

        EVENT LOGS TESTED:
        1. Application Log (read access)
           - Required for agent to write operational events
        2. InventoryAgent Event Source (check if exists)
           - Custom event source for agent logging
        3. Security Log (read access)
           - Required for logon event detection (Event ID 4624)

        EVENT LOG PERMISSIONS:
        - Application Log: Read/Write required
        - Security Log: Read-only required
        - Event sources created at install time (requires admin)

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - Event source creation requires administrator privileges
        - SYSTEM account has full event log access
        - Security log readable by administrators only
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "Event Log Access Checks"

    # === CHECK 1: APPLICATION LOG READ ACCESS ===
    try {
        [System.Diagnostics.EventLogEntry[]]$Events = Get-EventLog -LogName Application -Newest 1 -ErrorAction Stop

        Write-TestResult -TestName "Application Event Log Read" `
                         -Status "PASS" `
                         -Message "Successfully read Application log" `
                         -Details @{LogName="Application"}
    }
    catch {
        Write-TestResult -TestName "Application Event Log Read" `
                         -Status "FAIL" `
                         -Message "Cannot read Application log" `
                         -Remediation "Verify user has Event Log Readers permissions" `
                         -Details @{Error=$_.Exception.Message}
    }

    # === CHECK 2: INVENTORY AGENT EVENT SOURCE ===
    try {
        [bool]$SourceExists = [System.Diagnostics.EventLog]::SourceExists("InventoryAgent")

        if ($SourceExists) {
            Write-TestResult -TestName "InventoryAgent Event Source" `
                             -Status "PASS" `
                             -Message "Event source already exists" `
                             -Details @{SourceName="InventoryAgent"}
        }
        else {
            Write-TestResult -TestName "InventoryAgent Event Source" `
                             -Status "WARN" `
                             -Message "Event source does not exist (will be created during install)" `
                             -Remediation "Pre-create via: New-EventLog -LogName Application -Source 'InventoryAgent'" `
                             -Details @{SourceName="InventoryAgent"; Exists=$false}
        }
    }
    catch {
        Write-TestResult -TestName "InventoryAgent Event Source" `
                         -Status "INFO" `
                         -Message "Cannot check event source (may require elevation)" `
                         -Details @{Error=$_.Exception.Message}
    }

    # === CHECK 3: SECURITY LOG READ ACCESS ===
    # Required for logon event detection (Event ID 4624)
    # Non-administrators typically cannot read Security log
    try {
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$Events = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop

        Write-TestResult -TestName "Security Event Log Read" `
                         -Status "PASS" `
                         -Message "Successfully read Security log (required for logon detection)" `
                         -Details @{LogName="Security"}
    }
    catch {
        Write-TestResult -TestName "Security Event Log Read" `
                         -Status "WARN" `
                         -Message "Cannot read Security log" `
                         -Remediation "Scheduled task will run as SYSTEM and has access. Non-admin users cannot read Security log." `
                         -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Network Connectivity Checks
function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
        Tests network connectivity to inventory server.

    .DESCRIPTION
        Validates end-to-end network connectivity including:
        1. DNS resolution
        2. TCP connectivity
        3. HTTPS request
        4. Proxy detection

        NETWORK REQUIREMENTS:
        - DNS: Must resolve server hostname
        - Firewall: Outbound HTTPS (TCP 443) allowed
        - Proxy: HTTP proxy supported with Windows integrated auth
        - TLS: TLS 1.2 or higher required

    .PARAMETER ServerEndpoint
        [string] Server endpoint to test (e.g., "https://inventory.company.com")

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - Tests actual HTTPS connectivity (not just DNS/TCP)
        - Detects system proxy configuration
        - Validates TLS version support
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServerEndpoint
    )

    Write-TestHeader "Network Connectivity Checks"

    # Parse server endpoint URL
    try {
        [System.Uri]$Uri = [System.Uri]$ServerEndpoint
        [string]$Hostname = $Uri.Host
        [int]$Port = if ($Uri.Port -gt 0) { $Uri.Port } else { 443 }

        Write-Host "  Testing connection to: $Hostname`:$Port" -ForegroundColor Cyan

        # === CHECK 1: DNS RESOLUTION ===
        try {
            [Microsoft.DnsClient.Commands.DnsRecord[]]$DnsResult = Resolve-DnsName -Name $Hostname -ErrorAction Stop

            Write-TestResult -TestName "DNS Resolution" `
                             -Status "PASS" `
                             -Message "Successfully resolved $Hostname" `
                             -Details @{Hostname=$Hostname; Addresses=$DnsResult.IPAddress}
        }
        catch {
            Write-TestResult -TestName "DNS Resolution" `
                             -Status "FAIL" `
                             -Message "Cannot resolve $Hostname" `
                             -Remediation "Check DNS configuration and connectivity" `
                             -Details @{Hostname=$Hostname; Error=$_.Exception.Message}
            return
        }

        # === CHECK 2: TCP CONNECTIVITY ===
        # Test raw TCP socket connection (no SSL)
        try {
            [System.Net.Sockets.TcpClient]$TcpClient = New-Object System.Net.Sockets.TcpClient
            [System.IAsyncResult]$Connect = $TcpClient.BeginConnect($Hostname, $Port, $null, $null)
            [bool]$Wait = $Connect.AsyncWaitHandle.WaitOne(5000, $false)  # 5 second timeout

            if ($Wait) {
                $TcpClient.EndConnect($Connect)
                $TcpClient.Close()

                Write-TestResult -TestName "TCP Connectivity" `
                                 -Status "PASS" `
                                 -Message "Successfully connected to $Hostname`:$Port" `
                                 -Details @{Hostname=$Hostname; Port=$Port}
            }
            else {
                Write-TestResult -TestName "TCP Connectivity" `
                                 -Status "FAIL" `
                                 -Message "Connection timeout to $Hostname`:$Port" `
                                 -Remediation "Check firewall rules and network connectivity" `
                                 -Details @{Hostname=$Hostname; Port=$Port}
            }
        }
        catch {
            Write-TestResult -TestName "TCP Connectivity" `
                             -Status "FAIL" `
                             -Message "Cannot connect to $Hostname`:$Port" `
                             -Remediation "Check firewall rules and network connectivity" `
                             -Details @{Hostname=$Hostname; Port=$Port; Error=$_.Exception.Message}
        }

        # === CHECK 3: HTTPS REQUEST ===
        # Test full HTTPS connection with TLS 1.2+
        try {
            # Force TLS 1.2 or higher
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            [Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri "$ServerEndpoint/health" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

            Write-TestResult -TestName "HTTPS Request" `
                             -Status "PASS" `
                             -Message "Successfully connected via HTTPS (Status: $($Response.StatusCode))" `
                             -Details @{StatusCode=$Response.StatusCode; Endpoint="$ServerEndpoint/health"}
        }
        catch {
            [int]$StatusCode = $_.Exception.Response.StatusCode.Value__

            if ($StatusCode) {
                Write-TestResult -TestName "HTTPS Request" `
                                 -Status "WARN" `
                                 -Message "Server returned HTTP $StatusCode" `
                                 -Remediation "Verify API endpoint is correct and server is operational" `
                                 -Details @{StatusCode=$StatusCode; Error=$_.Exception.Message}
            }
            else {
                Write-TestResult -TestName "HTTPS Request" `
                                 -Status "FAIL" `
                                 -Message "HTTPS request failed" `
                                 -Remediation "Check SSL/TLS settings and proxy configuration" `
                                 -Details @{Error=$_.Exception.Message}
            }
        }

        # === CHECK 4: PROXY DETECTION ===
        # Detect system proxy configuration
        [System.Net.IWebProxy]$ProxySettings = [System.Net.WebRequest]::GetSystemWebProxy()
        [System.Uri]$ProxyUri = $ProxySettings.GetProxy($Uri)

        if ($ProxyUri.AbsoluteUri -ne $Uri.AbsoluteUri) {
            Write-TestResult -TestName "Proxy Configuration" `
                             -Status "WARN" `
                             -Message "System proxy detected: $($ProxyUri.AbsoluteUri)" `
                             -Remediation "Ensure inventory agent config includes proxy settings if authentication is required" `
                             -Details @{ProxyUri=$ProxyUri.AbsoluteUri}
        }
        else {
            Write-TestResult -TestName "Proxy Configuration" `
                             -Status "PASS" `
                             -Message "No proxy required for this endpoint" `
                             -Details @{ProxyConfigured=$false}
        }
    }
    catch {
        Write-TestResult -TestName "Network Connectivity" `
                         -Status "FAIL" `
                         -Message "Invalid server endpoint: $ServerEndpoint" `
                         -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Certificate Store Checks
function Test-CertificateAccess {
    <#
    .SYNOPSIS
        Tests certificate store access and code signing certificate availability.

    .DESCRIPTION
        Validates access to LocalMachine certificate store and checks for
        code signing certificates (if script signing is required).

        CERTIFICATE REQUIREMENTS:
        - LocalMachine\My store access (for client certificates)
        - Code signing certificate (if AllSigned execution policy)
        - Certificates deployed via GPO in enterprise environments

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - Certificate store access typically requires local admin
        - SYSTEM account has full certificate store access
        - Code signing certificates have "Code Signing" EKU
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "Certificate Store Access Checks"

    # === CHECK 1: CERTIFICATE STORE ACCESS ===
    try {
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop

        Write-TestResult -TestName "Certificate Store Access" `
                         -Status "PASS" `
                         -Message "Successfully accessed LocalMachine\My store ($($Certs.Count) certificates)" `
                         -Details @{Store="LocalMachine\My"; CertCount=$Certs.Count}

        # === CHECK 2: CODE SIGNING CERTIFICATE ===
        # Filter for certificates with Code Signing EKU
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$CodeSignCerts = $Certs | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }

        if ($CodeSignCerts) {
            Write-TestResult -TestName "Code Signing Certificate" `
                             -Status "PASS" `
                             -Message "Found $($CodeSignCerts.Count) code signing certificate(s)" `
                             -Details @{Count=$CodeSignCerts.Count; Subjects=($CodeSignCerts | ForEach-Object { $_.Subject })}
        }
        else {
            Write-TestResult -TestName "Code Signing Certificate" `
                             -Status "WARN" `
                             -Message "No code signing certificates found" `
                             -Remediation "Deploy code signing certificate via GPO if script signing is required" `
                             -Details @{Found=$false}
        }
    }
    catch {
        Write-TestResult -TestName "Certificate Store Access" `
                         -Status "FAIL" `
                         -Message "Cannot access certificate store" `
                         -Remediation "Verify permissions to LocalMachine certificate store" `
                         -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Security Software Checks
function Test-SecuritySoftware {
    <#
    .SYNOPSIS
        Detects security software (AV/EDR) that may interfere.

    .DESCRIPTION
        Checks for Windows Defender and common EDR solutions.
        Security software may:
        - Block PowerShell execution
        - Quarantine scripts
        - Slow WMI queries
        - Block network connections

        COMMON EDR PRODUCTS DETECTED:
        - CrowdStrike Falcon
        - SentinelOne
        - Carbon Black
        - Cylance
        - Tanium
        - Sysmon

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - Detection based on process names (not foolproof)
        - Presence doesn't guarantee blocking (depends on policy)
        - Recommend adding exclusions for agent path
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "Security Software Checks"

    # === CHECK 1: WINDOWS DEFENDER ===
    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

        if ($DefenderStatus.AntivirusEnabled) {
            Write-TestResult -TestName "Windows Defender" `
                             -Status "INFO" `
                             -Message "Windows Defender is active" `
                             -Remediation "Consider adding exclusion for C:\ProgramData\InventoryAgent\ to reduce scanning overhead" `
                             -Details @{Enabled=$true; RealTimeProtectionEnabled=$DefenderStatus.RealTimeProtectionEnabled}

            # Check for existing exclusions
            $DefenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue

            if ($DefenderPrefs.ExclusionPath -contains "C:\ProgramData\InventoryAgent") {
                Write-TestResult -TestName "Defender Exclusion" `
                                 -Status "PASS" `
                                 -Message "Inventory agent path is already excluded" `
                                 -Details @{ExclusionConfigured=$true}
            }
            else {
                Write-TestResult -TestName "Defender Exclusion" `
                                 -Status "WARN" `
                                 -Message "No exclusion configured for agent path" `
                                 -Remediation "Add-MpPreference -ExclusionPath 'C:\ProgramData\InventoryAgent'" `
                                 -Details @{ExclusionConfigured=$false}
            }
        }
        else {
            Write-TestResult -TestName "Windows Defender" `
                             -Status "INFO" `
                             -Message "Windows Defender is disabled or not present" `
                             -Details @{Enabled=$false}
        }
    }
    catch {
        Write-TestResult -TestName "Windows Defender" `
                         -Status "INFO" `
                         -Message "Cannot query Windows Defender status" `
                         -Details @{Error=$_.Exception.Message}
    }

    # === CHECK 2: EDR DETECTION ===
    # List of common EDR process names
    [string[]]$EDRProcesses = @(
        "CrowdStrike", "SentinelOne", "CarbonBlack", "Cylance",
        "TaniumClient", "SysmonDrv", "csagent", "xagt"
    )

    [System.Collections.ArrayList]$DetectedEDR = @()

    foreach ($EDRName in $EDRProcesses) {
        [System.Diagnostics.Process[]]$Process = Get-Process -Name $EDRName -ErrorAction SilentlyContinue
        if ($Process) {
            [void]$DetectedEDR.Add($EDRName)
        }
    }

    if ($DetectedEDR.Count -gt 0) {
        Write-TestResult -TestName "EDR Detection" `
                         -Status "WARN" `
                         -Message "Detected EDR/Security software: $($DetectedEDR -join ', ')" `
                         -Remediation "Coordinate with security team to add necessary exclusions or allow rules" `
                         -Details @{DetectedSoftware=$DetectedEDR.ToArray()}
    }
    else {
        Write-TestResult -TestName "EDR Detection" `
                         -Status "INFO" `
                         -Message "No common EDR software detected via process names" `
                         -Details @{Detected=$false}
    }
}
#endregion

#region File System Checks
function Test-FileSystemAccess {
    <#
    .SYNOPSIS
        Tests file system access for agent installation directory.

    .DESCRIPTION
        Validates ability to create directory and write files to
        C:\ProgramData\InventoryAgent (default installation path).

        TESTS PERFORMED:
        1. Directory creation
        2. File write permissions
        3. Directory cleanup (if created for test)

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - ProgramData is accessible to SYSTEM account
        - Typically requires admin for directory creation
        - NTFS permissions inherited from parent
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "File System Access Checks"

    [string]$TargetPath = "C:\ProgramData\InventoryAgent"

    # Test directory creation
    try {
        [bool]$Created = $false

        if (!(Test-Path -Path $TargetPath)) {
            New-Item -ItemType Directory -Path $TargetPath -Force -ErrorAction Stop | Out-Null
            $Created = $true
        }

        Write-TestResult -TestName "Target Directory" `
                         -Status "PASS" `
                         -Message "Successfully accessed/created $TargetPath" `
                         -Details @{Path=$TargetPath; Created=$Created}

        # Test write permissions
        [string]$TestFile = Join-Path -Path $TargetPath -ChildPath "test_$(Get-Random).tmp"
        "Test" | Out-File -FilePath $TestFile -Force -ErrorAction Stop
        Remove-Item -Path $TestFile -Force

        Write-TestResult -TestName "Write Permissions" `
                         -Status "PASS" `
                         -Message "Successfully wrote test file to $TargetPath" `
                         -Details @{Path=$TargetPath}

        # Cleanup if we created the directory
        if ($Created) {
            Remove-Item -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-TestResult -TestName "File System Access" `
                         -Status "FAIL" `
                         -Message "Cannot create/write to $TargetPath" `
                         -Remediation "Verify SYSTEM account has Full Control permissions" `
                         -Details @{Path=$TargetPath; Error=$_.Exception.Message}
    }
}
#endregion

#region Scheduled Task Checks
function Test-ScheduledTaskCapability {
    <#
    .SYNOPSIS
        Tests Task Scheduler service and task creation capability.

    .DESCRIPTION
        Validates Task Scheduler service status and ability to create
        scheduled tasks. Agent relies on scheduled tasks for automation.

        TESTS PERFORMED:
        1. Task Scheduler service status
        2. Test task creation and deletion

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Results written via Write-TestResult.

    .NOTES
        - Task Scheduler service must be running
        - Task creation requires administrator privileges
        - Tasks created as NT AUTHORITY\SYSTEM
    #>
    [CmdletBinding()]
    param()

    Write-TestHeader "Scheduled Task Checks"

    # === CHECK 1: TASK SCHEDULER SERVICE ===
    try {
        [System.ServiceProcess.ServiceController]$TaskScheduler = Get-Service -Name "Schedule" -ErrorAction Stop

        if ($TaskScheduler.Status -eq "Running") {
            Write-TestResult -TestName "Task Scheduler Service" `
                             -Status "PASS" `
                             -Message "Task Scheduler service is running" `
                             -Details @{Status=$TaskScheduler.Status}
        }
        else {
            Write-TestResult -TestName "Task Scheduler Service" `
                             -Status "FAIL" `
                             -Message "Task Scheduler service is not running: $($TaskScheduler.Status)" `
                             -Remediation "Start the Schedule service" `
                             -Details @{Status=$TaskScheduler.Status}
        }
    }
    catch {
        Write-TestResult -TestName "Task Scheduler Service" `
                         -Status "FAIL" `
                         -Message "Cannot query Task Scheduler service" `
                         -Details @{Error=$_.Exception.Message}
    }

    # === CHECK 2: TASK CREATION TEST ===
    try {
        [string]$TestTaskName = "Test-InventoryDeployment-$(Get-Random)"
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ActionType]$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -Command 'Write-Output Test'"
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.TriggerType]$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(60)
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.PrincipalType]$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

        Register-ScheduledTask -TaskName $TestTaskName -Action $Action -Trigger $Trigger -Principal $Principal -ErrorAction Stop | Out-Null

        # Cleanup
        Unregister-ScheduledTask -TaskName $TestTaskName -Confirm:$false -ErrorAction SilentlyContinue

        Write-TestResult -TestName "Task Creation Test" `
                         -Status "PASS" `
                         -Message "Successfully created and removed test scheduled task" `
                         -Details @{TestTaskName=$TestTaskName}
    }
    catch {
        Write-TestResult -TestName "Task Creation Test" `
                         -Status "FAIL" `
                         -Message "Cannot create scheduled tasks" `
                         -Remediation "Verify administrator privileges and Task Scheduler service" `
                         -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Main Execution
<#
    MAIN EXECUTION BLOCK
    Runs all test categories and displays summary.
#>

Write-Host "`n" -NoNewline
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "║     INVENTORY AGENT DEPLOYMENT READINESS CHECKER          ║" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  User: $env:USERNAME" -ForegroundColor White
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""

# Run all test categories
Test-PowerShellEnvironment
Test-ApplicationControl
Test-WMIAccess
Test-EventLogAccess
Test-NetworkConnectivity -ServerEndpoint $ServerEndpoint
Test-CertificateAccess
Test-SecuritySoftware
Test-FileSystemAccess
Test-ScheduledTaskCapability

# === SUMMARY ===
Write-TestHeader "Deployment Readiness Summary"

if ($script:Results.CriticalIssues -eq 0 -and $script:Results.Warnings -eq 0) {
    $script:Results.OverallStatus = "READY"
    Write-Host "  ✓ " -ForegroundColor Green -NoNewline
    Write-Host "Environment is READY for deployment" -ForegroundColor Green
}
elseif ($script:Results.CriticalIssues -eq 0) {
    $script:Results.OverallStatus = "READY_WITH_WARNINGS"
    Write-Host "  ⚠ " -ForegroundColor Yellow -NoNewline
    Write-Host "Environment is ready but has $($script:Results.Warnings) warning(s)" -ForegroundColor Yellow
}
else {
    $script:Results.OverallStatus = "NOT_READY"
    Write-Host "  ✗ " -ForegroundColor Red -NoNewline
    Write-Host "Environment is NOT READY - $($script:Results.CriticalIssues) critical issue(s) must be resolved" -ForegroundColor Red
}

Write-Host ""
Write-Host "  Test Results:" -ForegroundColor Cyan
Write-Host "    Passed: $($script:Results.Passed)" -ForegroundColor Green
Write-Host "    Warnings: $($script:Results.Warnings)" -ForegroundColor Yellow
Write-Host "    Critical Issues: $($script:Results.CriticalIssues)" -ForegroundColor Red

# Export report if requested
if ($ExportReport) {
    try {
        $script:Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Force
        Write-Host "`n  Report exported to: $ReportPath" -ForegroundColor Cyan
    }
    catch {
        Write-Host "`n  Failed to export report: $_" -ForegroundColor Red
    }
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

# Exit with appropriate code
if ($script:Results.CriticalIssues -gt 0) {
    exit 1
}
else {
    exit 0
}
#endregion
