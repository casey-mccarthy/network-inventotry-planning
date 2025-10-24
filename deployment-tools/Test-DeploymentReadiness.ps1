<#
.SYNOPSIS
    Validates environment readiness for Inventory Agent deployment
.DESCRIPTION
    This script checks for common security controls that could block
    the inventory agent deployment and provides remediation guidance.

    Checks include:
    - PowerShell version and execution policy
    - Constrained Language Mode detection
    - AppLocker/WDAC policies
    - WMI/CIM access permissions
    - Event Log access
    - Network connectivity and proxy configuration
    - Certificate store access
    - Antivirus/EDR status

.PARAMETER ServerEndpoint
    The inventory server endpoint to test connectivity
.PARAMETER Detailed
    Show detailed output for all checks
.PARAMETER ExportReport
    Export results to JSON file

.EXAMPLE
    .\Test-DeploymentReadiness.ps1 -ServerEndpoint "https://inventory.company.com"

.NOTES
    Version: 1.0.0
    Author: IT Operations
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ServerEndpoint = "https://inventory.company.com",

    [Parameter()]
    [switch]$Detailed,

    [Parameter()]
    [switch]$ExportReport,

    [Parameter()]
    [string]$ReportPath = ".\DeploymentReadinessReport.json"
)

# Color codes for output
$script:Colors = @{
    Pass = "Green"
    Fail = "Red"
    Warning = "Yellow"
    Info = "Cyan"
    Header = "Magenta"
}

$script:Results = @{
    TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    Checks = @()
    OverallStatus = "Unknown"
    CriticalIssues = 0
    Warnings = 0
    Passed = 0
}

function Write-TestHeader {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor $Colors.Header
    Write-Host $Title -ForegroundColor $Colors.Header
    Write-Host "========================================" -ForegroundColor $Colors.Header
}

function Write-TestResult {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Message,
        [string]$Remediation = "",
        [object]$Details = $null
    )

    $Result = @{
        TestName = $TestName
        Status = $Status
        Message = $Message
        Remediation = $Remediation
        Details = $Details
    }

    $script:Results.Checks += $Result

    $StatusColor = switch ($Status) {
        "PASS" { $Colors.Pass; $script:Results.Passed++ }
        "FAIL" { $Colors.Fail; $script:Results.CriticalIssues++ }
        "WARN" { $Colors.Warning; $script:Results.Warnings++ }
        default { $Colors.Info }
    }

    $StatusSymbol = switch ($Status) {
        "PASS" { "✓" }
        "FAIL" { "✗" }
        "WARN" { "⚠" }
        default { "●" }
    }

    Write-Host "  $StatusSymbol " -ForegroundColor $StatusColor -NoNewline
    Write-Host "$TestName : " -NoNewline
    Write-Host $Message -ForegroundColor $StatusColor

    if ($Detailed -and $Remediation) {
        Write-Host "    Remediation: $Remediation" -ForegroundColor Yellow
    }

    if ($Detailed -and $Details) {
        Write-Host "    Details: $($Details | ConvertTo-Json -Compress)" -ForegroundColor Gray
    }
}

#region PowerShell Environment Checks
function Test-PowerShellEnvironment {
    Write-TestHeader "PowerShell Environment Checks"

    # Check PowerShell version
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -ge 5 -and $PSVersion.Minor -ge 1) {
        Write-TestResult -TestName "PowerShell Version" -Status "PASS" -Message "Version $($PSVersion.ToString()) is supported" -Details $PSVersion
    }
    else {
        Write-TestResult -TestName "PowerShell Version" -Status "FAIL" -Message "Version $($PSVersion.ToString()) is too old" -Remediation "Upgrade to PowerShell 5.1 or higher" -Details $PSVersion
    }

    # Check Execution Policy
    $ExecutionPolicy = Get-ExecutionPolicy -Scope LocalMachine
    $PolicyStatus = switch ($ExecutionPolicy) {
        "Restricted" { "FAIL" }
        "Undefined" { "WARN" }
        "Bypass" { "PASS" }
        "RemoteSigned" { "PASS" }
        "AllSigned" { "WARN" }
        "Unrestricted" { "PASS" }
        default { "WARN" }
    }

    $PolicyMessage = "Current policy: $ExecutionPolicy"
    $PolicyRemediation = if ($ExecutionPolicy -eq "Restricted") {
        "Set execution policy via GPO: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
    }
    elseif ($ExecutionPolicy -eq "AllSigned") {
        "Ensure all scripts are digitally signed, or change policy to RemoteSigned"
    }
    else { "" }

    Write-TestResult -TestName "Execution Policy" -Status $PolicyStatus -Message $PolicyMessage -Remediation $PolicyRemediation -Details @{Policy=$ExecutionPolicy; Scope="LocalMachine"}

    # Check Language Mode
    $LanguageMode = $ExecutionContext.SessionState.LanguageMode
    if ($LanguageMode -eq "ConstrainedLanguage") {
        Write-TestResult -TestName "Language Mode" -Status "WARN" -Message "Constrained Language Mode detected" -Remediation "Agent is compatible but compression features will be disabled" -Details @{Mode=$LanguageMode}
    }
    elseif ($LanguageMode -eq "FullLanguage") {
        Write-TestResult -TestName "Language Mode" -Status "PASS" -Message "Full Language Mode available" -Details @{Mode=$LanguageMode}
    }
    else {
        Write-TestResult -TestName "Language Mode" -Status "WARN" -Message "Unexpected Language Mode: $LanguageMode" -Details @{Mode=$LanguageMode}
    }

    # Check if running as administrator
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($IsAdmin) {
        Write-TestResult -TestName "Administrator Rights" -Status "PASS" -Message "Running with administrator privileges" -Details @{IsAdmin=$IsAdmin}
    }
    else {
        Write-TestResult -TestName "Administrator Rights" -Status "WARN" -Message "Not running as administrator (required for installation)" -Remediation "Run as administrator to install scheduled tasks" -Details @{IsAdmin=$IsAdmin}
    }
}
#endregion

#region Application Control Checks
function Test-ApplicationControl {
    Write-TestHeader "Application Control Checks"

    # Check AppLocker status
    try {
        $AppLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop

        if ($AppLockerPolicy) {
            $RuleCount = 0
            foreach ($RuleCollection in $AppLockerPolicy.RuleCollections) {
                $RuleCount += $RuleCollection.Count
            }

            if ($RuleCount -gt 0) {
                Write-TestResult -TestName "AppLocker Policy" -Status "WARN" -Message "AppLocker is active with $RuleCount rules" -Remediation "Create AppLocker rules to allow C:\ProgramData\InventoryAgent\* and PowerShell.exe" -Details @{RuleCount=$RuleCount; Collections=$AppLockerPolicy.RuleCollections.Count}

                # Check for PowerShell-specific rules
                $PSRules = $AppLockerPolicy.RuleCollections | Where-Object { $_.RuleCollectionType -eq "Script" }
                if ($PSRules -and $PSRules.Count -gt 0) {
                    Write-TestResult -TestName "AppLocker Script Rules" -Status "WARN" -Message "PowerShell script rules detected ($($PSRules.Count) rules)" -Remediation "Ensure inventory scripts are allowed by publisher or path rule" -Details @{ScriptRules=$PSRules.Count}
                }
            }
            else {
                Write-TestResult -TestName "AppLocker Policy" -Status "PASS" -Message "AppLocker policy exists but no rules configured" -Details @{RuleCount=0}
            }
        }
        else {
            Write-TestResult -TestName "AppLocker Policy" -Status "PASS" -Message "No AppLocker policy detected" -Details @{Configured=$false}
        }
    }
    catch {
        Write-TestResult -TestName "AppLocker Policy" -Status "INFO" -Message "Unable to query AppLocker status (may not be configured)" -Details @{Error=$_.Exception.Message}
    }

    # Check WDAC (Windows Defender Application Control) - Windows 10/11
    try {
        $CIPolicy = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CIPolicyInfo -ErrorAction Stop

        if ($CIPolicy) {
            Write-TestResult -TestName "WDAC Policy" -Status "WARN" -Message "Windows Defender Application Control is active" -Remediation "Create WDAC allow rules for inventory agent scripts and PowerShell" -Details @{PolicyCount=$CIPolicy.Count}
        }
        else {
            Write-TestResult -TestName "WDAC Policy" -Status "PASS" -Message "No WDAC policy detected" -Details @{Configured=$false}
        }
    }
    catch {
        Write-TestResult -TestName "WDAC Policy" -Status "PASS" -Message "WDAC not configured or not supported" -Details @{Configured=$false}
    }
}
#endregion

#region WMI/CIM Access Checks
function Test-WMIAccess {
    Write-TestHeader "WMI/CIM Access Checks"

    $WMIClasses = @(
        @{Class="Win32_BIOS"; Required=$true; Description="System serial number and BIOS info"},
        @{Class="Win32_ComputerSystem"; Required=$true; Description="Computer name, domain, manufacturer"},
        @{Class="Win32_OperatingSystem"; Required=$true; Description="OS version and boot time"},
        @{Class="Win32_Processor"; Required=$true; Description="CPU information"},
        @{Class="Win32_DiskDrive"; Required=$true; Description="Disk serial numbers"},
        @{Class="Win32_NetworkAdapterConfiguration"; Required=$true; Description="Network adapter info"}
    )

    foreach ($WMITest in $WMIClasses) {
        try {
            $Result = Get-CimInstance -ClassName $WMITest.Class -ErrorAction Stop | Select-Object -First 1

            if ($Result) {
                Write-TestResult -TestName "WMI: $($WMITest.Class)" -Status "PASS" -Message "Successfully queried $($WMITest.Description)" -Details @{Class=$WMITest.Class}
            }
            else {
                Write-TestResult -TestName "WMI: $($WMITest.Class)" -Status "WARN" -Message "Query succeeded but returned no data" -Details @{Class=$WMITest.Class}
            }
        }
        catch {
            $Status = if ($WMITest.Required) { "FAIL" } else { "WARN" }
            Write-TestResult -TestName "WMI: $($WMITest.Class)" -Status $Status -Message "Access denied or query failed" -Remediation "Verify WMI service is running and user has WMI permissions" -Details @{Class=$WMITest.Class; Error=$_.Exception.Message}
        }
    }
}
#endregion

#region Event Log Access Checks
function Test-EventLogAccess {
    Write-TestHeader "Event Log Access Checks"

    # Test reading Application log
    try {
        $Events = Get-EventLog -LogName Application -Newest 1 -ErrorAction Stop
        Write-TestResult -TestName "Application Event Log Read" -Status "PASS" -Message "Successfully read Application log" -Details @{LogName="Application"}
    }
    catch {
        Write-TestResult -TestName "Application Event Log Read" -Status "FAIL" -Message "Cannot read Application log" -Remediation "Verify user has Event Log Readers permissions" -Details @{Error=$_.Exception.Message}
    }

    # Test if InventoryAgent event source exists
    try {
        $SourceExists = [System.Diagnostics.EventLog]::SourceExists("InventoryAgent")

        if ($SourceExists) {
            Write-TestResult -TestName "InventoryAgent Event Source" -Status "PASS" -Message "Event source already exists" -Details @{SourceName="InventoryAgent"}
        }
        else {
            Write-TestResult -TestName "InventoryAgent Event Source" -Status "WARN" -Message "Event source does not exist (will be created during install)" -Remediation "Pre-create via: New-EventLog -LogName Application -Source 'InventoryAgent'" -Details @{SourceName="InventoryAgent"; Exists=$false}
        }
    }
    catch {
        Write-TestResult -TestName "InventoryAgent Event Source" -Status "INFO" -Message "Cannot check event source (may require elevation)" -Details @{Error=$_.Exception.Message}
    }

    # Test reading Security log (for logon events)
    try {
        $Events = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
        Write-TestResult -TestName "Security Event Log Read" -Status "PASS" -Message "Successfully read Security log (required for logon detection)" -Details @{LogName="Security"}
    }
    catch {
        Write-TestResult -TestName "Security Event Log Read" -Status "WARN" -Message "Cannot read Security log" -Remediation "Scheduled task will run as SYSTEM and has access. Non-admin users cannot read Security log." -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Network Connectivity Checks
function Test-NetworkConnectivity {
    param([string]$ServerEndpoint)

    Write-TestHeader "Network Connectivity Checks"

    # Parse server endpoint
    try {
        $Uri = [System.Uri]$ServerEndpoint
        $Hostname = $Uri.Host
        $Port = if ($Uri.Port -gt 0) { $Uri.Port } else { 443 }

        Write-Host "  Testing connection to: $Hostname`:$Port" -ForegroundColor Cyan

        # DNS resolution
        try {
            $DnsResult = Resolve-DnsName -Name $Hostname -ErrorAction Stop
            Write-TestResult -TestName "DNS Resolution" -Status "PASS" -Message "Successfully resolved $Hostname" -Details @{Hostname=$Hostname; Addresses=$DnsResult.IPAddress}
        }
        catch {
            Write-TestResult -TestName "DNS Resolution" -Status "FAIL" -Message "Cannot resolve $Hostname" -Remediation "Check DNS configuration and connectivity" -Details @{Hostname=$Hostname; Error=$_.Exception.Message}
            return
        }

        # TCP connectivity
        try {
            $TcpClient = New-Object System.Net.Sockets.TcpClient
            $Connect = $TcpClient.BeginConnect($Hostname, $Port, $null, $null)
            $Wait = $Connect.AsyncWaitHandle.WaitOne(5000, $false)

            if ($Wait) {
                $TcpClient.EndConnect($Connect)
                $TcpClient.Close()
                Write-TestResult -TestName "TCP Connectivity" -Status "PASS" -Message "Successfully connected to $Hostname`:$Port" -Details @{Hostname=$Hostname; Port=$Port}
            }
            else {
                Write-TestResult -TestName "TCP Connectivity" -Status "FAIL" -Message "Connection timeout to $Hostname`:$Port" -Remediation "Check firewall rules and network connectivity" -Details @{Hostname=$Hostname; Port=$Port}
            }
        }
        catch {
            Write-TestResult -TestName "TCP Connectivity" -Status "FAIL" -Message "Cannot connect to $Hostname`:$Port" -Remediation "Check firewall rules and network connectivity" -Details @{Hostname=$Hostname; Port=$Port; Error=$_.Exception.Message}
        }

        # HTTPS request
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $Response = Invoke-WebRequest -Uri "$ServerEndpoint/health" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

            Write-TestResult -TestName "HTTPS Request" -Status "PASS" -Message "Successfully connected via HTTPS (Status: $($Response.StatusCode))" -Details @{StatusCode=$Response.StatusCode; Endpoint="$ServerEndpoint/health"}
        }
        catch {
            $StatusCode = $_.Exception.Response.StatusCode.Value__
            if ($StatusCode) {
                Write-TestResult -TestName "HTTPS Request" -Status "WARN" -Message "Server returned HTTP $StatusCode" -Remediation "Verify API endpoint is correct and server is operational" -Details @{StatusCode=$StatusCode; Error=$_.Exception.Message}
            }
            else {
                Write-TestResult -TestName "HTTPS Request" -Status "FAIL" -Message "HTTPS request failed" -Remediation "Check SSL/TLS settings and proxy configuration" -Details @{Error=$_.Exception.Message}
            }
        }

        # Proxy detection
        $ProxySettings = [System.Net.WebRequest]::GetSystemWebProxy()
        $ProxyUri = $ProxySettings.GetProxy($Uri)

        if ($ProxyUri.AbsoluteUri -ne $Uri.AbsoluteUri) {
            Write-TestResult -TestName "Proxy Configuration" -Status "WARN" -Message "System proxy detected: $($ProxyUri.AbsoluteUri)" -Remediation "Ensure inventory agent config includes proxy settings if authentication is required" -Details @{ProxyUri=$ProxyUri.AbsoluteUri}
        }
        else {
            Write-TestResult -TestName "Proxy Configuration" -Status "PASS" -Message "No proxy required for this endpoint" -Details @{ProxyConfigured=$false}
        }
    }
    catch {
        Write-TestResult -TestName "Network Connectivity" -Status "FAIL" -Message "Invalid server endpoint: $ServerEndpoint" -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Certificate Store Checks
function Test-CertificateAccess {
    Write-TestHeader "Certificate Store Access Checks"

    # Test LocalMachine\My store access
    try {
        $Certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop

        Write-TestResult -TestName "Certificate Store Access" -Status "PASS" -Message "Successfully accessed LocalMachine\My store ($($Certs.Count) certificates)" -Details @{Store="LocalMachine\My"; CertCount=$Certs.Count}

        # Check for code signing certificates
        $CodeSignCerts = $Certs | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }

        if ($CodeSignCerts) {
            Write-TestResult -TestName "Code Signing Certificate" -Status "PASS" -Message "Found $($CodeSignCerts.Count) code signing certificate(s)" -Details @{Count=$CodeSignCerts.Count; Subjects=($CodeSignCerts | ForEach-Object { $_.Subject })}
        }
        else {
            Write-TestResult -TestName "Code Signing Certificate" -Status "WARN" -Message "No code signing certificates found" -Remediation "Deploy code signing certificate via GPO if script signing is required" -Details @{Found=$false}
        }
    }
    catch {
        Write-TestResult -TestName "Certificate Store Access" -Status "FAIL" -Message "Cannot access certificate store" -Remediation "Verify permissions to LocalMachine certificate store" -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Antivirus/Security Software Checks
function Test-SecuritySoftware {
    Write-TestHeader "Security Software Checks"

    # Check Windows Defender status
    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

        if ($DefenderStatus.AntivirusEnabled) {
            Write-TestResult -TestName "Windows Defender" -Status "INFO" -Message "Windows Defender is active" -Remediation "Consider adding exclusion for C:\ProgramData\InventoryAgent\ to reduce scanning overhead" -Details @{Enabled=$true; RealTimeProtectionEnabled=$DefenderStatus.RealTimeProtectionEnabled}

            # Check for existing exclusions
            $DefenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue
            if ($DefenderPrefs.ExclusionPath -contains "C:\ProgramData\InventoryAgent") {
                Write-TestResult -TestName "Defender Exclusion" -Status "PASS" -Message "Inventory agent path is already excluded" -Details @{ExclusionConfigured=$true}
            }
            else {
                Write-TestResult -TestName "Defender Exclusion" -Status "WARN" -Message "No exclusion configured for agent path" -Remediation "Add-MpPreference -ExclusionPath 'C:\ProgramData\InventoryAgent'" -Details @{ExclusionConfigured=$false}
            }
        }
        else {
            Write-TestResult -TestName "Windows Defender" -Status "INFO" -Message "Windows Defender is disabled or not present" -Details @{Enabled=$false}
        }
    }
    catch {
        Write-TestResult -TestName "Windows Defender" -Status "INFO" -Message "Cannot query Windows Defender status" -Details @{Error=$_.Exception.Message}
    }

    # Check for common EDR solutions (basic detection)
    $EDRProcesses = @(
        "CrowdStrike",
        "SentinelOne",
        "CarbonBlack",
        "Cylance",
        "TaniumClient",
        "SysmonDrv",
        "csagent",
        "xagt"
    )

    $DetectedEDR = @()
    foreach ($EDRName in $EDRProcesses) {
        $Process = Get-Process -Name $EDRName -ErrorAction SilentlyContinue
        if ($Process) {
            $DetectedEDR += $EDRName
        }
    }

    if ($DetectedEDR.Count -gt 0) {
        Write-TestResult -TestName "EDR Detection" -Status "WARN" -Message "Detected EDR/Security software: $($DetectedEDR -join ', ')" -Remediation "Coordinate with security team to add necessary exclusions or allow rules" -Details @{DetectedSoftware=$DetectedEDR}
    }
    else {
        Write-TestResult -TestName "EDR Detection" -Status "INFO" -Message "No common EDR software detected via process names" -Details @{Detected=$false}
    }
}
#endregion

#region File System Checks
function Test-FileSystemAccess {
    Write-TestHeader "File System Access Checks"

    $TargetPath = "C:\ProgramData\InventoryAgent"

    # Test directory creation
    try {
        if (!(Test-Path $TargetPath)) {
            New-Item -ItemType Directory -Path $TargetPath -Force -ErrorAction Stop | Out-Null
            $Created = $true
        }
        else {
            $Created = $false
        }

        Write-TestResult -TestName "Target Directory" -Status "PASS" -Message "Successfully accessed/created $TargetPath" -Details @{Path=$TargetPath; Created=$Created}

        # Test write permissions
        $TestFile = Join-Path $TargetPath "test_$(Get-Random).tmp"
        "Test" | Out-File -FilePath $TestFile -Force -ErrorAction Stop
        Remove-Item -Path $TestFile -Force

        Write-TestResult -TestName "Write Permissions" -Status "PASS" -Message "Successfully wrote test file to $TargetPath" -Details @{Path=$TargetPath}

        # Cleanup if we created it
        if ($Created) {
            Remove-Item -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-TestResult -TestName "File System Access" -Status "FAIL" -Message "Cannot create/write to $TargetPath" -Remediation "Verify SYSTEM account has Full Control permissions" -Details @{Path=$TargetPath; Error=$_.Exception.Message}
    }
}
#endregion

#region Scheduled Task Checks
function Test-ScheduledTaskCapability {
    Write-TestHeader "Scheduled Task Checks"

    # Check if Task Scheduler service is running
    try {
        $TaskScheduler = Get-Service -Name "Schedule" -ErrorAction Stop

        if ($TaskScheduler.Status -eq "Running") {
            Write-TestResult -TestName "Task Scheduler Service" -Status "PASS" -Message "Task Scheduler service is running" -Details @{Status=$TaskScheduler.Status}
        }
        else {
            Write-TestResult -TestName "Task Scheduler Service" -Status "FAIL" -Message "Task Scheduler service is not running: $($TaskScheduler.Status)" -Remediation "Start the Schedule service" -Details @{Status=$TaskScheduler.Status}
        }
    }
    catch {
        Write-TestResult -TestName "Task Scheduler Service" -Status "FAIL" -Message "Cannot query Task Scheduler service" -Details @{Error=$_.Exception.Message}
    }

    # Test task creation capability
    try {
        $TestTaskName = "Test-InventoryDeployment-$(Get-Random)"
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -Command 'Write-Output Test'"
        $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(60)
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

        Register-ScheduledTask -TaskName $TestTaskName -Action $Action -Trigger $Trigger -Principal $Principal -ErrorAction Stop | Out-Null

        # Cleanup
        Unregister-ScheduledTask -TaskName $TestTaskName -Confirm:$false -ErrorAction SilentlyContinue

        Write-TestResult -TestName "Task Creation Test" -Status "PASS" -Message "Successfully created and removed test scheduled task" -Details @{TestTaskName=$TestTaskName}
    }
    catch {
        Write-TestResult -TestName "Task Creation Test" -Status "FAIL" -Message "Cannot create scheduled tasks" -Remediation "Verify administrator privileges and Task Scheduler service" -Details @{Error=$_.Exception.Message}
    }
}
#endregion

#region Main Execution
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

# Run all checks
Test-PowerShellEnvironment
Test-ApplicationControl
Test-WMIAccess
Test-EventLogAccess
Test-NetworkConnectivity -ServerEndpoint $ServerEndpoint
Test-CertificateAccess
Test-SecuritySoftware
Test-FileSystemAccess
Test-ScheduledTaskCapability

# Summary
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
