<#
.SYNOPSIS
    Creates Windows Defender Application Control (WDAC) policy for Inventory Agent

.DESCRIPTION
    This script generates a WDAC (formerly known as Device Guard) Code Integrity policy
    that allows the Inventory Agent to run while maintaining system security.

    WDAC is more secure than AppLocker and is the recommended application control
    mechanism for Windows 10/11 in high-security environments.

.PARAMETER PolicyPath
    Path where the WDAC policy XML will be saved

.PARAMETER PolicyName
    Name for the WDAC policy

.PARAMETER EnforceMode
    Whether to create policy in Audit or Enforced mode

.PARAMETER IncludeSignedScripts
    Include rules for signed PowerShell scripts

.PARAMETER IncludeCompiledAgent
    Include rules for compiled .NET agent executable

.NOTES
    Version: 1.0.0
    Requires: Windows 10 1903+ or Windows 11
    Requires: Administrator privileges

.EXAMPLE
    .\Create-WDACPolicy.ps1 -PolicyName "InventoryAgent" -EnforceMode Audit

.EXAMPLE
    .\Create-WDACPolicy.ps1 -PolicyName "InventoryAgent" -EnforceMode Enforced -IncludeSignedScripts -IncludeCompiledAgent
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter()]
    [string]$PolicyPath = ".\InventoryAgent-WDAC-Policy.xml",

    [Parameter()]
    [string]$PolicyName = "Inventory Agent Policy",

    [Parameter()]
    [ValidateSet("Audit", "Enforced")]
    [string]$EnforceMode = "Audit",

    [Parameter()]
    [switch]$IncludeSignedScripts,

    [Parameter()]
    [switch]$IncludeCompiledAgent,

    [Parameter()]
    [string]$CodeSigningCertThumbprint = "",

    [Parameter()]
    [string]$AgentInstallPath = "C:\ProgramData\InventoryAgent"
)

function Write-PolicyLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )

    $Colors = @{
        Info = "Cyan"
        Warning = "Yellow"
        Error = "Red"
        Success = "Green"
    }

    Write-Host "[$Level] $Message" -ForegroundColor $Colors[$Level]
}

function Test-WDACSupport {
    Write-PolicyLog "Checking WDAC support..." "Info"

    # Check Windows version
    $OSVersion = [System.Environment]::OSVersion.Version

    if ($OSVersion.Major -lt 10) {
        Write-PolicyLog "WDAC requires Windows 10 or later" "Error"
        return $false
    }

    if ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 18362) {
        Write-PolicyLog "WDAC requires Windows 10 1903 (build 18362) or later" "Error"
        return $false
    }

    # Check if ConfigCI module is available
    $ConfigCI = Get-Module -ListAvailable -Name ConfigCI -ErrorAction SilentlyContinue

    if (-not $ConfigCI) {
        Write-PolicyLog "ConfigCI PowerShell module not found. Install RSAT or Windows SDK." "Error"
        return $false
    }

    Import-Module ConfigCI -ErrorAction Stop
    Write-PolicyLog "WDAC is supported on this system" "Success"
    return $true
}

function New-InventoryAgentWDACPolicy {
    Write-PolicyLog "========================================" "Info"
    Write-PolicyLog "Creating WDAC Policy: $PolicyName" "Info"
    Write-PolicyLog "========================================" "Info"

    # Check WDAC support
    if (-not (Test-WDACSupport)) {
        return $false
    }

    # Create base policy from Windows default policy
    Write-PolicyLog "Creating base policy..." "Info"

    # Option 1: Start with DefaultWindows template (most permissive)
    # Option 2: Start with AllowMicrosoft template (more restrictive)
    $BaseTemplate = "AllowMicrosoft"

    $TempPolicyPath = "$env:TEMP\BasePolicy-$((Get-Random)).xml"

    try {
        # Create base policy allowing Microsoft-signed code
        New-CIPolicy -Level Publisher `
            -FilePath $TempPolicyPath `
            -UserPEs `
            -MultiplePolicyFormat `
            -Fallback Hash `
            -ErrorAction Stop

        Write-PolicyLog "Base policy created successfully" "Success"
    }
    catch {
        Write-PolicyLog "Failed to create base policy: $_" "Error"
        return $false
    }

    # Set policy information
    Write-PolicyLog "Configuring policy metadata..." "Info"

    Set-CIPolicyIdInfo -FilePath $TempPolicyPath `
        -PolicyName $PolicyName `
        -PolicyId "InventoryAgent_$(Get-Date -Format 'yyyyMMdd')" `
        -ErrorAction SilentlyContinue

    # Add PowerShell script rules if requested
    if ($IncludeSignedScripts) {
        Write-PolicyLog "Adding rules for signed PowerShell scripts..." "Info"

        if (Test-Path $AgentInstallPath) {
            # Scan the install directory for scripts
            $ScriptFiles = Get-ChildItem -Path $AgentInstallPath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue

            if ($ScriptFiles) {
                # Create supplemental policy for scripts
                $SupplementalPolicyPath = "$env:TEMP\SupplementalPolicy-Scripts-$((Get-Random)).xml"

                try {
                    New-CIPolicy -Level Publisher `
                        -FilePath $SupplementalPolicyPath `
                        -ScanPath $AgentInstallPath `
                        -UserPEs `
                        -MultiplePolicyFormat `
                        -Fallback Hash

                    # Merge supplemental policy into base
                    Merge-CIPolicy -PolicyPaths @($TempPolicyPath, $SupplementalPolicyPath) -OutputFilePath $TempPolicyPath

                    Remove-Item $SupplementalPolicyPath -Force
                    Write-PolicyLog "PowerShell script rules added" "Success"
                }
                catch {
                    Write-PolicyLog "Failed to add script rules: $_" "Warning"
                }
            }
            else {
                Write-PolicyLog "No PowerShell scripts found in $AgentInstallPath" "Warning"
            }
        }
        else {
            Write-PolicyLog "Agent install path not found: $AgentInstallPath" "Warning"
        }
    }

    # Add compiled agent rules if requested
    if ($IncludeCompiledAgent) {
        Write-PolicyLog "Adding rules for compiled agent executable..." "Info"

        $ExePath = "C:\Program Files\InventoryAgent\InventoryAgent.exe"

        if (Test-Path $ExePath) {
            $SupplementalPolicyPath = "$env:TEMP\SupplementalPolicy-Exe-$((Get-Random)).xml"

            try {
                New-CIPolicy -Level Publisher `
                    -FilePath $SupplementalPolicyPath `
                    -DriverFiles $ExePath `
                    -UserPEs `
                    -MultiplePolicyFormat `
                    -Fallback Hash

                # Merge supplemental policy
                Merge-CIPolicy -PolicyPaths @($TempPolicyPath, $SupplementalPolicyPath) -OutputFilePath $TempPolicyPath

                Remove-Item $SupplementalPolicyPath -Force
                Write-PolicyLog "Compiled agent rules added" "Success"
            }
            catch {
                Write-PolicyLog "Failed to add executable rules: $_" "Warning"
            }
        }
        else {
            Write-PolicyLog "Agent executable not found: $ExePath" "Warning"
        }
    }

    # Add certificate-based rule if thumbprint provided
    if ($CodeSigningCertThumbprint) {
        Write-PolicyLog "Adding certificate-based rule..." "Info"

        try {
            $Cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $CodeSigningCertThumbprint }

            if ($Cert) {
                # Export certificate to file
                $CertPath = "$env:TEMP\CodeSignCert-$((Get-Random)).cer"
                Export-Certificate -Cert $Cert -FilePath $CertPath -Force | Out-Null

                # Create rule from certificate
                $SupplementalPolicyPath = "$env:TEMP\SupplementalPolicy-Cert-$((Get-Random)).xml"

                Add-SignerRule -FilePath $TempPolicyPath `
                    -CertificatePath $CertPath `
                    -Kernel -User `
                    -ErrorAction Stop

                Remove-Item $CertPath -Force
                Write-PolicyLog "Certificate-based rule added" "Success"
            }
            else {
                Write-PolicyLog "Certificate not found: $CodeSigningCertThumbprint" "Warning"
            }
        }
        catch {
            Write-PolicyLog "Failed to add certificate rule: $_" "Warning"
        }
    }

    # Configure policy rules
    Write-PolicyLog "Configuring policy rules..." "Info"

    # Set policy to Audit or Enforced mode
    if ($EnforceMode -eq "Audit") {
        Write-PolicyLog "Setting policy to Audit mode (recommended for testing)" "Info"
        Set-RuleOption -FilePath $TempPolicyPath -Option 3  # 3 = Audit Mode
    }
    else {
        Write-PolicyLog "Setting policy to Enforced mode" "Warning"
        Set-RuleOption -FilePath $TempPolicyPath -Option 3 -Delete  # Remove audit mode
    }

    # Enable additional security options
    Set-RuleOption -FilePath $TempPolicyPath -Option 0   # Enabled:UMCI (User Mode Code Integrity)
    Set-RuleOption -FilePath $TempPolicyPath -Option 2   # Enabled:Whql (Require WHQL for drivers)
    Set-RuleOption -FilePath $TempPolicyPath -Option 5   # Enabled:Inherit Default Policy
    Set-RuleOption -FilePath $TempPolicyPath -Option 6   # Enabled:Unsigned System Integrity Policy
    Set-RuleOption -FilePath $TempPolicyPath -Option 9   # Enabled:Advanced Boot Options Menu
    Set-RuleOption -FilePath $TempPolicyPath -Option 10  # Enabled:Boot Menu Protection
    Set-RuleOption -FilePath $TempPolicyPath -Option 12  # Enabled:Enforce Store Applications
    Set-RuleOption -FilePath $TempPolicyPath -Option 16  # Enabled:No Reboot Required
    Set-RuleOption -FilePath $TempPolicyPath -Option 17  # Enabled:Allow Supplemental Policies
    Set-RuleOption -FilePath $TempPolicyPath -Option 19  # Enabled:Dynamic Code Security

    # Save final policy
    Copy-Item -Path $TempPolicyPath -Destination $PolicyPath -Force
    Remove-Item $TempPolicyPath -Force

    Write-PolicyLog "========================================" "Success"
    Write-PolicyLog "WDAC Policy created successfully!" "Success"
    Write-PolicyLog "Policy saved to: $PolicyPath" "Success"
    Write-PolicyLog "========================================" "Success"

    # Provide deployment instructions
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
    Write-Host "   Event ID 3077 = Allowed" -ForegroundColor White
    Write-Host ""

    if ($EnforceMode -eq "Audit") {
        Write-Host "IMPORTANT: Policy is in AUDIT MODE" -ForegroundColor Yellow
        Write-Host "Monitor for 2-4 weeks before switching to Enforced mode" -ForegroundColor Yellow
        Write-Host ""
    }

    return $true
}

# Execute
$Result = New-InventoryAgentWDACPolicy

if ($Result) {
    exit 0
}
else {
    Write-PolicyLog "Policy creation failed" "Error"
    exit 1
}
