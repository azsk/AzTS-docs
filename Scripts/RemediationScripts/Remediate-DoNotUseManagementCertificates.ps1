<###
# Overview:
    This script is used to remove management certificates from a Subscription.

# Control ID:
    Azure_Subscription_AuthZ_Remove_Management_Certs

# Display Name:
    Do not use management certificates.

# Prerequisites:
    Service Administrator or Co-Administrator for a Subscription.

# Steps performed by the script:
    1. Validate and install the modules required to run the script.
    2. Get the list of management certificates in a Subscription.
    3. Back up details of management certificates that are to be remediated.
    4. Delete management certificates from a Subscription.

# Instructions to execute the script:
    1. Download the script.
    2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
    3. Execute the script to delete management certificates from a Subscription. Refer `Examples`, below.

# Examples:
    1. To review the certificates in a Subscription that will be deleted:
    
       Remove-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

    2. To remove all management certificates from a Subscription:
       
       Remove-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

    3. To remove certificates in a Subscription, from a previously taken snapshot:
       
       Remove-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\ManagementCertificates.csv

    To know more about the options supported by the remediation command, execute:
        
    Get-Help Remove-ManagementCertificates -Detailed
###>


function Setup-Prerequisites
{
    <#
        .SYNOPSIS
        Checks if the prerequisites are met, else, sets them up.

        .DESCRIPTION
        Checks if the prerequisites are met, else, sets them up.
        Includes installing any required Azure modules.

        .INPUTS
        None. You cannot pipe objects to Setup-Prerequisites.

        .OUTPUTS
        None. Setup-Prerequisites does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Setup-Prerequisites

        .LINK
        None
    #>

    # List of required modules
    $requiredModules = @("Az.Accounts", "Azure")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}


function Remove-ManagementCertificates
{
    <#
        .SYNOPSIS
        Remediates 'Azure_Subscription_AuthZ_Remove_Management_Certs' Control.

        .DESCRIPTION
        Remediates 'Azure_Subscription_AuthZ_Remove_Management_Certs' Control.
        Deletes any management certificates present in a Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Remove-ManagementCertificates.

        .OUTPUTS
        None. Remove-ManagementCertificates does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Remove-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Remove-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Remove-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveManagementCertificates\ManagementCertificates.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to delete management certificates from Subscription: $($SubscriptionId)"

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if $($context.Account.Id) is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "*** Only Service Administrators and Co-Administrators on a Subscription can delete management certificates. ***" -ForegroundColor $([Constants]::MessageType.Info)

    # Only Service Administrators and Co-Administrators can run this script.
    $eligibleRoles = @("ServiceAdministrator", "CoAdministrator")

    # Instantiate an instance of `AuthenticationHelper`. This instance will be used to fetch access tokens for use in APIs.
    [AuthenticationHelper] $authHelper = [AuthenticationHelper]::new([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)

    # Instantiate an instance of `ManagementCertificate`. This has methods to GET/DELETE management certificates.
    [ManagementCertificate] $managementCertificate = [ManagementCertificate]::new([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)

    $armBaseUri = "https://management.azure.com"
    $scope = "https://management.core.windows.net/"

    $accessToken = $authHelper.GetAccessToken($scope)

    # Get all Classic Administrators in a Subscription.
    $getClassicAdminsUri = "$($armBaseUri)/subscriptions/$($context.Subscription.SubscriptionId)/providers/Microsoft.Authorization/classicadministrators?api-version=2015-06-01"
    $headers = @{"Authorization"=$($accessToken)}
    $response = Invoke-WebRequest -Method Get -Uri $getClassicAdminsUri -Headers $headers -UseBasicParsing -ErrorAction Stop

    # Get the email address and role associated with every Classic Administrator role assignment.
    $classicAdmins = (($response.Content | ConvertFrom-Json).value) | select @{N='Email';E={$_.properties.emailAddress}} | Where-Object { $_.Email -eq $context.Account.Id -and $eligibleRoles -match ($_.Role) }

    # Determine if the current user has the required permissions to run this script.
    $canRunScript = $($($classicAdmins | Measure-Object).Count -gt 0)

    if (-not $canRunScript)
    {
        Write-Host "This script can only be run by one of: $($eligibleRoles -join ", ")" -ForegroundColor $([Constants]::MessageType.Error)
        break
    }
    else
    {
        Write-Host "$($context.Account.Id) has the required permissions." -ForegroundColor $([Constants]::MessageType.Update)
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all management certificates..."

    $certificates = @()

    # No file path provided as input to the script. Fetch all management certificates in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all management certificates for Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)
        $certificateDetails = [XML]$managementCertificate.GetBySubscriptionId($context.Subscription.SubscriptionId)
        $certificates = $certificateDetails.GetElementsByTagName("SubscriptionCertificate") | ForEach-Object { $_ | Select-Object @{N='SubscriptionCertificateThumbprint';E={$_.SubscriptionCertificateThumbprint}},
                                                                                                                                  @{N='Created';E={$_.Created}}
                                                                                                             }
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all management certificates from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
        $certificateDetails = Import-Csv -LiteralPath $FilePath
        $certificates = $certificateDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.SubscriptionCertificateThumbprint) }
    }

    $totalCertificates = ($certificates | Measure-Object).Count

    if ($totalCertificates -eq 0)
    {
        Write-Host "No management certificates found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
  
    Write-Host "Found $($totalCertificates) certificate(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemoveManagementCertificates"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up management certificate details to $($backupFolderPath)"
    
    # Backing up management certificate details.
    $backupFile = "$($backupFolderPath)\ManagementCertificates.csv"

    $certificates | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {
        Write-Host "Certificate details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "Rollback is not possible. This script does not back up certificates and certificates once deleted cannot be restored by this script." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "*** Recommended: Back up the certificates manually, prior to removing them. ***" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "If the same certificates are still required post remediation, use $($backupFile) as a reference and manually upload the certificates." -ForegroundColor $([Constants]::MessageType.Warning)

        if (-not $Force)
        {
            Write-Host "Do you want to delete all the certificates? " -ForegroundColor $([Constants]::MessageType.Update) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Certificates will not be deleted. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Certificates will be deleted without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Deleting management certificates..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $certificatesDeleted = @()
        $certificatesSkipped = @()

        $certificates | ForEach-Object {
            $certificate = $_
            $certificateThumbprint = $_.SubscriptionCertificateThumbprint

            Write-Host "Deleting certificate with thumbprint: $($certificateThumbprint)" -ForegroundColor $([Constants]::MessageType.Warning)

            try
            {
                $response = $managementCertificate.DeleteByCertificateThumbprint($context.Subscription.SubscriptionId, $certificateThumbprint)

                if ($response.StatusCode -eq 200)
                {
                    $certificatesDeleted += $certificate
                    Write-Host "Successfully deleted certificate with thumbprint: $($certificateThumbprint)" -ForegroundColor $([Constants]::MessageType.Update)
                }
                else
                {
                    # Error would have been already logged inside the actual method.
                    $certificatesSkipped += $certificate
                }
            }
            catch
            {
                $certificatesSkipped += $certificate
                Write-Host "Error deleting certificate with thumbprint: $($certificateThumbprint). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }

        if (($certificatesDeleted | Measure-Object).Count -eq $totalCertificates)
        {
            Write-Host "All $($totalCertificates) certificate(s) successfully deleted." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "$($($certificatesDeleted | Measure-Object).Count) out of $($totalCertificates) certificate(s) successfully deleted." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.SubscriptionCertificateThumbprint};Label="SubscriptionCertificateThumbprint";Width=40},
                        @{Expression={$_.Created};Label="Created";Width=40}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($certificatesDeleted | Measure-Object).Count -gt 0)
        {
            Write-Host "The following certificate(s) have been successfully deleted:" -ForegroundColor $([Constants]::MessageType.Update)
            $certificatesDeleted | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $certificatesDeletedFile = "$($backupFolderPath)\DeletedCertificates.csv"
            $certificatesDeleted | Export-CSV -Path $certificatesDeletedFile -NoTypeInformation
            Write-Host "This information has been saved to $($certificatesDeletedFile)"
        }

        if ($($certificatesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nThe following certificate(s) could not be successfully deleted:" -ForegroundColor $([Constants]::MessageType.Error)
            $certificatesSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $certificatesSkippedFile = "$($backupFolderPath)\SkippedCertificates.csv"
            $certificatesSkipped | Export-CSV -Path $certificatesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($certificatesSkippedFile)"
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Certificate details have been backed up to $($backupFile). Please review before removing them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to remove all the certificates listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }
}

# Defines standard methods to manage REST authentication to Azure.
class AuthenticationHelper
{
    # Members of the class
    [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context

    # Constructor
    AuthenticationHelper([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)
    {
        $this.context = $context
    }

    # Gets the access token for the scope denoted by $scope.
    [String] GetAccessToken([String] $scope)
    {
        [String] $accessToken = [String]::Empty

        try
        {
            $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                $this.context.Account,
                $this.context.Environment,
                $this.context.Tenant,
                [System.Security.SecureString] $null,
                "Never",
                $null,
                $scope)
            
            if ([String]::IsNullOrWhiteSpace($authResult))
            {
                Write-Host "Access token is NULL or empty. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            $accessToken = "Bearer " + $authResult.AccessToken
        }
        catch
        {
            Write-Host "Error occurred while fetching access token. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        return $accessToken
    }
}

# Defines standard method to handle management certificates.
class ManagementCertificate
{
    # Members of the class
    [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context

    # Constructor
    ManagementCertificate([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)
    {
        $this.context = $context
    }

    # Gets all management certificates in the Subscription denoted by SubscriptionId.
    [PSObject] GetBySubscriptionId([String] $subscriptionId)
    {
        $scope = "https://management.core.windows.net/"

        [AuthenticationHelper] $authHelper = [AuthenticationHelper]::new([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $this.context)
        $accessToken = $authHelper.GetAccessToken($scope)

        [PSObject] $certificates = New-Object PSObject

        try
        {
            $getCertificatesUri = "https://management.core.windows.net/$($subscriptionId)/certificates"
            $headers = @{"Authorization"=$($accessToken);"x-ms-version"="2014-11-01"}
            $response = Invoke-WebRequest -Method Get -Uri $getCertificatesUri -Headers $headers -UseBasicParsing -ContentType "application/xml" -ErrorAction Stop
            $certificates = $response.Content
        }
        catch
        {
            Write-Host "Error occurred while fetching management certificates. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
        
        return $certificates
    }

    # Deletes the management certificate denoted by thumbprint.
    [PSObject] DeleteByCertificateThumbprint([String] $subscriptionId, [String] $thumbprint)
    {
        $scope = "https://management.core.windows.net/"

        [AuthenticationHelper] $authHelper = [AuthenticationHelper]::new([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $this.context)
        $accessToken = $authHelper.GetAccessToken($scope)

        [PSObject] $response = New-Object PSObject

        try
        {
            $deleteCertificateUri = "https://management.core.windows.net/$($subscriptionId)/certificates/$($thumbprint)"
            $headers = @{"Authorization"=$($accessToken);"x-ms-version"="2014-11-01"}
            $response = Invoke-WebRequest -Method Delete -Uri $deleteCertificateUri -Headers $headers -UseBasicParsing -ContentType "application/xml" -ErrorAction SilentlyContinue
        }
        catch
        {
            Write-Host "Error occurred while deleting management certificate with thumbprint: $($thumbprint). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
        
        return $response
    }
}

# Defines commonly used constants.
class Constants
{
    # Defines commonly used colour codes, corresponding to the severity of the log.
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}
