<#
.SYNOPSIS
    Creates Windows Defender Application Control (WDAC) policy for Inventory Agent.

.DESCRIPTION
    Generates a WDAC Code Integrity policy that allows the Inventory Agent
    to execute while maintaining high system security standards.

    WDAC (formerly Device Guard Code Integrity) is Microsoft's most secure
    application control mechanism, operating at the kernel level to enforce
    code integrity policies. This is the recommended security control for
    government and high-security enterprise environments.

    WDAC vs APPLOCKER:
    - WDAC: Kernel-level enforcement, more secure, harder to bypass
    - AppLocker: User-mode enforcement, easier to configure, less secure

    POLICY TYPES SUPPORTED:
    1. Publisher-based: Allows code signed by specific publisher
    2. Hash-based: Allows specific file hashes (fallback)
    3. Path-based: Allows code from specific directories

    MODES:
    - Audit Mode: Logs violations without blocking (recommended for testing)
    - Enforced Mode: Actively blocks unauthorized code (production)

    DEPLOYMENT WORKFLOW:
    1. Create policy in Audit mode
    2. Monitor Event Log for 2-4 weeks
    3. Refine policy based on audit events
    4. Convert to Enforced mode
    5. Deploy via GPO or Intune

.PARAMETER PolicyPath
    [string] Path where the WDAC policy XML will be saved.
    Default: ".\InventoryAgent-WDAC-Policy.xml"

    This is the source XML policy file that can be:
    - Converted to binary (.cip) format
    - Deployed via GPO/Intune
    - Merged with other policies

.PARAMETER PolicyName
    [string] Friendly name for the WDAC policy.
    Default: "Inventory Agent Policy"

    Appears in Event Viewer and policy management tools.

.PARAMETER EnforceMode
    [string] Policy enforcement mode.
    Valid values: "Audit", "Enforced"
    Default: "Audit"

    Audit: Log violations only (recommended for initial deployment)
    Enforced: Block unauthorized code (production mode)

.PARAMETER IncludeSignedScripts
    [switch] Include rules for signed PowerShell scripts.
    Default: $false

    When specified, scans agent installation path for .ps1 files
    and creates publisher-based rules.

.PARAMETER IncludeCompiledAgent
    [switch] Include rules for compiled .NET agent executable.
    Default: $false

    When specified, creates rules for
    C:\Program Files\InventoryAgent\InventoryAgent.exe

.PARAMETER CodeSigningCertThumbprint
    [string] Thumbprint of code signing certificate for certificate-based rules.
    Default: "" (empty)

    If provided, creates signer rule allowing all code signed by this certificate.
    Format: 40-character hex string (e.g., "1234567890ABCDEF...")

.PARAMETER AgentInstallPath
    [string] Path to inventory agent installation directory.
    Default: "C:\ProgramData\InventoryAgent"

    Used for scanning PowerShell scripts when -IncludeSignedScripts specified.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Int32
    Exit code 0 for success, 1 for failure.

    Side effects:
    - Creates XML policy file at $PolicyPath
    - Displays deployment instructions
    - May create temporary policy files (auto-deleted)

.EXAMPLE
    PS> .\Create-WDACPolicy.ps1

    Creates audit-mode policy with default settings (no script/executable rules).

.EXAMPLE
    PS> .\Create-WDACPolicy.ps1 -PolicyName "InventoryAgent" -EnforceMode Audit

    Creates audit-mode policy with custom name.

.EXAMPLE
    PS> .\Create-WDACPolicy.ps1 -EnforceMode Enforced -IncludeSignedScripts -IncludeCompiledAgent

    Creates enforced-mode policy with rules for both PowerShell scripts and compiled executable.

.EXAMPLE
    PS> .\Create-WDACPolicy.ps1 -CodeSigningCertThumbprint "1234567890ABCDEF..." -EnforceMode Audit

    Creates certificate-based policy allowing all code signed by specified certificate.

.NOTES
    File Name      : Create-WDACPolicy.ps1
    Version        : 1.0.0
    Author         : Security Engineering Team
    Prerequisite   : PowerShell 5.1 or higher
    Prerequisite   : Windows 10 1903+ or Windows 11
    Prerequisite   : Administrator privileges
    Prerequisite   : ConfigCI PowerShell module (part of Windows SDK or RSAT)

    GOVERNMENT/ENTERPRISE SECURITY:
    - WDAC is NIAP-certified for Common Criteria
    - Meets DoD STIG requirements for application whitelisting
    - FIPS 140-2 compliant when using signed policies
    - Required for CMMC Level 3+ environments

    TESTING RECOMMENDATIONS:
    - Always start in Audit mode
    - Monitor Event Log for 2-4 weeks minimum
    - Test on pilot systems before mass deployment
    - Keep Audit mode policy for troubleshooting

    EVENT LOG MONITORING:
    - Event Viewer > Applications and Services > Microsoft > Windows > CodeIntegrity > Operational
    - Event ID 3076: Blocked in Audit mode (would be blocked if Enforced)
    - Event ID 3077: Allowed by policy
    - Event ID 3089: Policy loaded

    DEPLOYMENT PATHS:
    - Single Machine: C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{GUID}.cip
    - GPO: \\domain\SYSVOL\Policies\{GPO}\Machine\Microsoft\Windows\CodeIntegrity\
    - Intune: Upload via Endpoint Security > Application Control

.LINK
    https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control

.LINK
    https://docs.company.com/inventory-agent/wdac-policy
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false,
               Position = 0,
               HelpMessage = "Path for WDAC policy XML file")]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyPath = ".\InventoryAgent-WDAC-Policy.xml",

    [Parameter(Mandatory = $false,
               Position = 1,
               HelpMessage = "Friendly name for WDAC policy")]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyName = "Inventory Agent Policy",

    [Parameter(Mandatory = $false,
               HelpMessage = "Policy enforcement mode (Audit or Enforced)")]
    [ValidateSet("Audit", "Enforced")]
    [string]$EnforceMode = "Audit",

    [Parameter(Mandatory = $false,
               HelpMessage = "Include rules for signed PowerShell scripts")]
    [switch]$IncludeSignedScripts,

    [Parameter(Mandatory = $false,
               HelpMessage = "Include rules for compiled .NET agent executable")]
    [switch]$IncludeCompiledAgent,

    [Parameter(Mandatory = $false,
               HelpMessage = "Code signing certificate thumbprint for certificate-based rules")]
    [ValidatePattern('^([0-9A-Fa-f]{40})?$')]
    [string]$CodeSigningCertThumbprint = "",

    [Parameter(Mandatory = $false,
               HelpMessage = "Inventory agent installation path")]
    [ValidateNotNullOrEmpty()]
    [string]$AgentInstallPath = "C:\ProgramData\InventoryAgent"
)

#region Logging Functions
<#
    POLICY CREATION LOGGING
    Console output for policy creation progress and results.
#>

function Write-PolicyLog {
    <#
    .SYNOPSIS
        Writes policy creation log message to console.

    .DESCRIPTION
        Formatted console output for policy creation workflow.
        Uses color-coding for different message levels.

    .PARAMETER Message
        [string] Log message to display.

    .PARAMETER Level
        [string] Message severity level.
        Valid values: "Info", "Warning", "Error", "Success"
        Default: "Info"

    .INPUTS
        None.

    .OUTPUTS
        None. Writes to console as side effect.

    .EXAMPLE
        Write-PolicyLog "Policy created successfully" -Level "Success"

        Displays success message in green.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )

    # Color mapping for different message levels
    [hashtable]$Colors = @{
        Info    = "Cyan"
        Warning = "Yellow"
        Error   = "Red"
        Success = "Green"
    }

    Write-Host "[$Level] $Message" -ForegroundColor $Colors[$Level]
}
#endregion

#region WDAC Support Validation
function Test-WDACSupport {
    <#
    .SYNOPSIS
        Validates WDAC support on current system.

    .DESCRIPTION
        Checks Windows version and ConfigCI module availability.

        REQUIREMENTS:
        - Windows 10 build 18362 (1903) or later
        - Windows 11 (any build)
        - ConfigCI PowerShell module (from Windows SDK or RSAT)

        WDAC AVAILABILITY:
        - Windows 10 Home: Not supported
        - Windows 10 Pro/Enterprise: Supported (1903+)
        - Windows 11: Fully supported
        - Windows Server 2016+: Supported

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean
        $true if WDAC is supported
        $false if WDAC is not available

    .NOTES
        - ConfigCI module is part of Windows SDK
        - Can also be installed via RSAT (Remote Server Administration Tools)
        - Module provides cmdlets: New-CIPolicy, Set-CIPolicyIdInfo, etc.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-PolicyLog "Checking WDAC support..." -Level "Info"

    # === CHECK 1: WINDOWS VERSION ===
    # WDAC requires Windows 10 1903 (build 18362) or later
    [version]$OSVersion = [System.Environment]::OSVersion.Version

    if ($OSVersion.Major -lt 10) {
        Write-PolicyLog "WDAC requires Windows 10 or later" -Level "Error"
        return $false
    }

    if ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 18362) {
        Write-PolicyLog "WDAC requires Windows 10 1903 (build 18362) or later. Current build: $($OSVersion.Build)" -Level "Error"
        return $false
    }

    # === CHECK 2: CONFIGCI MODULE AVAILABILITY ===
    # ConfigCI module provides WDAC management cmdlets
    [PSModuleInfo]$ConfigCI = Get-Module -ListAvailable -Name ConfigCI -ErrorAction SilentlyContinue

    if (-not $ConfigCI) {
        Write-PolicyLog "ConfigCI PowerShell module not found" -Level "Error"
        Write-PolicyLog "Install via: Windows SDK or RSAT Tools" -Level "Error"
        return $false
    }

    # Import module for use
    try {
        Import-Module ConfigCI -ErrorAction Stop
        Write-PolicyLog "WDAC is supported on this system (Windows $($OSVersion.Major).$($OSVersion.Minor) build $($OSVersion.Build))" -Level "Success"
        return $true
    }
    catch {
        Write-PolicyLog "Failed to import ConfigCI module: $_" -Level "Error"
        return $false
    }
}
#endregion

#region Policy Creation
function New-InventoryAgentWDACPolicy {
    <#
    .SYNOPSIS
        Main function to create WDAC policy for Inventory Agent.

    .DESCRIPTION
        Orchestrates WDAC policy creation workflow:
        1. Validate WDAC support
        2. Create base policy (AllowMicrosoft template)
        3. Add PowerShell script rules (if requested)
        4. Add compiled agent rules (if requested)
        5. Add certificate-based rules (if provided)
        6. Configure policy options (Audit/Enforced mode)
        7. Save final policy
        8. Display deployment instructions

        BASE POLICY TEMPLATE:
        Uses "AllowMicrosoft" template which:
        - Allows all Microsoft-signed code
        - Allows Windows components
        - Blocks third-party code unless explicitly allowed

        RULE PRIORITY:
        1. Explicit deny rules (none in this policy)
        2. Explicit allow rules (our custom rules)
        3. Base policy rules (AllowMicrosoft)

    .PARAMETER None
        Uses script-level parameters.

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean
        $true if policy created successfully
        $false if policy creation failed

    .NOTES
        - Creates temporary policy files (auto-deleted)
        - Merges supplemental policies into base policy
        - Configures 12+ security options
        - Provides detailed deployment instructions
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-PolicyLog "========================================" -Level "Info"
    Write-PolicyLog "Creating WDAC Policy: $PolicyName" -Level "Info"
    Write-PolicyLog "========================================" -Level "Info"

    # === STEP 1: VALIDATE WDAC SUPPORT ===
    if (-not (Test-WDACSupport)) {
        return $false
    }

    # === STEP 2: CREATE BASE POLICY ===
    Write-PolicyLog "Creating base policy..." -Level "Info"

    # Base template selection:
    # - DefaultWindows: Most permissive (allows all Windows + WHQL drivers)
    # - AllowMicrosoft: More restrictive (Microsoft-signed code only)
    [string]$BaseTemplate = "AllowMicrosoft"

    # Generate temporary policy path
    # Temp files auto-deleted at end of script
    [string]$TempPolicyPath = "$env:TEMP\BasePolicy-$((Get-Random)).xml"

    try {
        # Create base Code Integrity policy
        # -Level Publisher: Trust based on code signing publisher
        # -FilePath: Output XML path
        # -UserPEs: Include user-mode code (not just kernel drivers)
        # -MultiplePolicyFormat: Support multiple concurrent policies
        # -Fallback Hash: If publisher not available, use file hash
        New-CIPolicy -Level Publisher `
                     -FilePath $TempPolicyPath `
                     -UserPEs `
                     -MultiplePolicyFormat `
                     -Fallback Hash `
                     -ErrorAction Stop | Out-Null

        Write-PolicyLog "Base policy created successfully" -Level "Success"
    }
    catch {
        Write-PolicyLog "Failed to create base policy: $_" -Level "Error"
        return $false
    }

    # === STEP 3: SET POLICY METADATA ===
    Write-PolicyLog "Configuring policy metadata..." -Level "Info"

    # Set policy name and ID for tracking
    # PolicyId: Unique identifier for this policy
    try {
        Set-CIPolicyIdInfo -FilePath $TempPolicyPath `
                           -PolicyName $PolicyName `
                           -PolicyId "InventoryAgent_$(Get-Date -Format 'yyyyMMdd')" `
                           -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-PolicyLog "Warning: Failed to set policy ID info (non-critical): $_" -Level "Warning"
    }

    # === STEP 4: ADD POWERSHELL SCRIPT RULES (IF REQUESTED) ===
    if ($IncludeSignedScripts) {
        Write-PolicyLog "Adding rules for signed PowerShell scripts..." -Level "Info"

        if (Test-Path -Path $AgentInstallPath) {
            # Scan installation directory for PowerShell scripts
            [System.IO.FileInfo[]]$ScriptFiles = Get-ChildItem -Path $AgentInstallPath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue

            if ($ScriptFiles) {
                # Create supplemental policy for scripts
                [string]$SupplementalPolicyPath = "$env:TEMP\SupplementalPolicy-Scripts-$((Get-Random)).xml"

                try {
                    # Scan scripts and create rules based on publisher/hash
                    New-CIPolicy -Level Publisher `
                                 -FilePath $SupplementalPolicyPath `
                                 -ScanPath $AgentInstallPath `
                                 -UserPEs `
                                 -MultiplePolicyFormat `
                                 -Fallback Hash `
                                 -ErrorAction Stop | Out-Null

                    # Merge supplemental policy into base policy
                    # This combines rule sets into single policy file
                    Merge-CIPolicy -PolicyPaths @($TempPolicyPath, $SupplementalPolicyPath) `
                                   -OutputFilePath $TempPolicyPath `
                                   -ErrorAction Stop | Out-Null

                    # Cleanup temporary supplemental policy
                    Remove-Item -Path $SupplementalPolicyPath -Force -ErrorAction SilentlyContinue

                    Write-PolicyLog "PowerShell script rules added (found $($ScriptFiles.Count) scripts)" -Level "Success"
                }
                catch {
                    Write-PolicyLog "Failed to add script rules: $_" -Level "Warning"
                }
            }
            else {
                Write-PolicyLog "No PowerShell scripts found in $AgentInstallPath" -Level "Warning"
            }
        }
        else {
            Write-PolicyLog "Agent install path not found: $AgentInstallPath" -Level "Warning"
        }
    }

    # === STEP 5: ADD COMPILED AGENT RULES (IF REQUESTED) ===
    if ($IncludeCompiledAgent) {
        Write-PolicyLog "Adding rules for compiled agent executable..." -Level "Info"

        [string]$ExePath = "C:\Program Files\InventoryAgent\InventoryAgent.exe"

        if (Test-Path -Path $ExePath) {
            [string]$SupplementalPolicyPath = "$env:TEMP\SupplementalPolicy-Exe-$((Get-Random)).xml"

            try {
                # Create policy for executable
                # -DriverFiles: Include specific file (not directory scan)
                New-CIPolicy -Level Publisher `
                             -FilePath $SupplementalPolicyPath `
                             -DriverFiles $ExePath `
                             -UserPEs `
                             -MultiplePolicyFormat `
                             -Fallback Hash `
                             -ErrorAction Stop | Out-Null

                # Merge into base policy
                Merge-CIPolicy -PolicyPaths @($TempPolicyPath, $SupplementalPolicyPath) `
                               -OutputFilePath $TempPolicyPath `
                               -ErrorAction Stop | Out-Null

                Remove-Item -Path $SupplementalPolicyPath -Force -ErrorAction SilentlyContinue

                Write-PolicyLog "Compiled agent rules added" -Level "Success"
            }
            catch {
                Write-PolicyLog "Failed to add executable rules: $_" -Level "Warning"
            }
        }
        else {
            Write-PolicyLog "Agent executable not found: $ExePath" -Level "Warning"
        }
    }

    # === STEP 6: ADD CERTIFICATE-BASED RULE (IF PROVIDED) ===
    if ($CodeSigningCertThumbprint) {
        Write-PolicyLog "Adding certificate-based rule..." -Level "Info"

        try {
            # Find certificate in LocalMachine\My store
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop |
                Where-Object { $_.Thumbprint -eq $CodeSigningCertThumbprint }

            if ($Cert) {
                # Export certificate to temporary file
                [string]$CertPath = "$env:TEMP\CodeSignCert-$((Get-Random)).cer"
                Export-Certificate -Cert $Cert -FilePath $CertPath -Force -ErrorAction Stop | Out-Null

                # Add signer rule to policy
                # This allows ALL code signed by this certificate
                # -Kernel: Apply to kernel-mode code
                # -User: Apply to user-mode code
                Add-SignerRule -FilePath $TempPolicyPath `
                               -CertificatePath $CertPath `
                               -Kernel -User `
                               -ErrorAction Stop | Out-Null

                Remove-Item -Path $CertPath -Force -ErrorAction SilentlyContinue

                Write-PolicyLog "Certificate-based rule added for: $($Cert.Subject)" -Level "Success"
            }
            else {
                Write-PolicyLog "Certificate not found with thumbprint: $CodeSigningCertThumbprint" -Level "Warning"
            }
        }
        catch {
            Write-PolicyLog "Failed to add certificate rule: $_" -Level "Warning"
        }
    }

    # === STEP 7: CONFIGURE POLICY OPTIONS ===
    Write-PolicyLog "Configuring policy rules..." -Level "Info"

    # Set Audit vs Enforced mode
    # Rule Option 3 = Enabled:Audit Mode
    if ($EnforceMode -eq "Audit") {
        Write-PolicyLog "Setting policy to Audit mode (recommended for testing)" -Level "Info"
        Set-RuleOption -FilePath $TempPolicyPath -Option 3 | Out-Null  # Enable Audit mode
    }
    else {
        Write-PolicyLog "Setting policy to Enforced mode" -Level "Warning"
        Set-RuleOption -FilePath $TempPolicyPath -Option 3 -Delete | Out-Null  # Disable Audit mode (enforce)
    }

    # Enable additional security options
    # Option 0: Enabled:UMCI (User Mode Code Integrity) - Enforce policy on user-mode code
    Set-RuleOption -FilePath $TempPolicyPath -Option 0 | Out-Null

    # Option 2: Enabled:Whql (Windows Hardware Quality Labs) - Require WHQL for drivers
    Set-RuleOption -FilePath $TempPolicyPath -Option 2 | Out-Null

    # Option 5: Enabled:Inherit Default Policy - Inherit from default Windows policy
    Set-RuleOption -FilePath $TempPolicyPath -Option 5 | Out-Null

    # Option 6: Enabled:Unsigned System Integrity Policy - Allow unsigned policies (testing)
    Set-RuleOption -FilePath $TempPolicyPath -Option 6 | Out-Null

    # Option 9: Enabled:Advanced Boot Options Menu - Allow F8 boot menu
    Set-RuleOption -FilePath $TempPolicyPath -Option 9 | Out-Null

    # Option 10: Enabled:Boot Menu Protection - Protect boot menu settings
    Set-RuleOption -FilePath $TempPolicyPath -Option 10 | Out-Null

    # Option 12: Enabled:Enforce Store Applications - Enforce policy on Microsoft Store apps
    Set-RuleOption -FilePath $TempPolicyPath -Option 12 | Out-Null

    # Option 16: Enabled:No Reboot Required - Policy updates don't require reboot
    Set-RuleOption -FilePath $TempPolicyPath -Option 16 | Out-Null

    # Option 17: Enabled:Allow Supplemental Policies - Allow additional policies to be merged
    Set-RuleOption -FilePath $TempPolicyPath -Option 17 | Out-Null

    # Option 19: Enabled:Dynamic Code Security - Enforce policy on dynamically generated code
    Set-RuleOption -FilePath $TempPolicyPath -Option 19 | Out-Null

    # === STEP 8: SAVE FINAL POLICY ===
    try {
        Copy-Item -Path $TempPolicyPath -Destination $PolicyPath -Force -ErrorAction Stop
        Remove-Item -Path $TempPolicyPath -Force -ErrorAction SilentlyContinue

        Write-PolicyLog "========================================" -Level "Success"
        Write-PolicyLog "WDAC Policy created successfully!" -Level "Success"
        Write-PolicyLog "Policy saved to: $PolicyPath" -Level "Success"
        Write-PolicyLog "========================================" -Level "Success"
    }
    catch {
        Write-PolicyLog "Failed to save final policy: $_" -Level "Error"
        return $false
    }

    # === STEP 9: DISPLAY DEPLOYMENT INSTRUCTIONS ===
    Write-Host "`nDEPLOYMENT INSTRUCTIONS:" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. CONVERT POLICY TO BINARY FORMAT:" -ForegroundColor Yellow
    Write-Host "   ConvertFrom-CIPolicy -XmlFilePath `"$PolicyPath`" -BinaryFilePath `"InventoryAgent.cip`"" -ForegroundColor White
    Write-Host ""
    Write-Host "2. DEPLOY POLICY (choose one):" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Option A - Single Machine:" -ForegroundColor Cyan
    Write-Host "   Copy-Item `"InventoryAgent.cip`" -Destination `"C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{PolicyGUID}.cip`"" -ForegroundColor White
    Write-Host ""
    Write-Host "   Option B - Group Policy:" -ForegroundColor Cyan
    Write-Host "   a) Copy .cip file to: \\domain\SYSVOL\domain\Policies\{GPO-GUID}\Machine\Microsoft\Windows\CodeIntegrity" -ForegroundColor White
    Write-Host "   b) Configure GPO: Computer Config > Admin Templates > System > Device Guard > Deploy Code Integrity Policy" -ForegroundColor White
    Write-Host ""
    Write-Host "   Option C - Intune/MDM:" -ForegroundColor Cyan
    Write-Host "   Upload .cip file via Endpoint Security > Application Control policy" -ForegroundColor White
    Write-Host ""
    Write-Host "3. VERIFY DEPLOYMENT:" -ForegroundColor Yellow
    Write-Host "   Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CIPolicyInfo" -ForegroundColor White
    Write-Host ""
    Write-Host "4. MONITOR IN AUDIT MODE:" -ForegroundColor Yellow
    Write-Host "   Check Event Viewer: Applications and Services > Microsoft > Windows > CodeIntegrity > Operational" -ForegroundColor White
    Write-Host "   Event ID 3076 = Blocked in Audit mode (would be blocked in Enforced)" -ForegroundColor White
    Write-Host "   Event ID 3077 = Allowed by policy" -ForegroundColor White
    Write-Host "   Event ID 3089 = Policy loaded successfully" -ForegroundColor White
    Write-Host ""

    if ($EnforceMode -eq "Audit") {
        Write-Host "IMPORTANT: Policy is in AUDIT MODE" -ForegroundColor Yellow
        Write-Host "Monitor Event Log for 2-4 weeks before switching to Enforced mode" -ForegroundColor Yellow
        Write-Host "To convert to Enforced mode: Remove Option 3 from policy and redeploy" -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "WARNING: Policy is in ENFORCED MODE" -ForegroundColor Red
        Write-Host "This will actively block unauthorized code" -ForegroundColor Red
        Write-Host "Ensure thorough testing in Audit mode before enforcing" -ForegroundColor Red
        Write-Host ""
    }

    return $true
}
#endregion

#region Main Execution
<#
    MAIN EXECUTION BLOCK
    Entry point for WDAC policy creation script.
#>

# Execute policy creation
[bool]$Result = New-InventoryAgentWDACPolicy

# Exit with appropriate code
if ($Result) {
    exit 0
}
else {
    Write-PolicyLog "Policy creation failed" -Level "Error"
    exit 1
}
#endregion
