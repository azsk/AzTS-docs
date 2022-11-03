<###
# Overview:
    This script is used to get Management Certificates in a Subscription.

# Prerequisites:
    1. Co-Admin or higher privileges in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
        1. Validate and install the modules required to run the script.
        2. Get the list of management certificate in a Subscription.

# Examples:
        1. To get the management certificates in a Subscription:
           Get-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
        2. To get the management certificates in a Subscription:
           Get-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000


        To know more about the options supported by the remediation command, execute:
        Get-Help Get-ManagementCertificates() -Detailed
        
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
    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "$($_) module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}


function Get-ManagementCertificates
{
    <#
        .SYNOPSIS
        Get the list of Management Certificates in a subscription

        .DESCRIPTION
        Get the list of Management Certificates in a subscription
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .INPUTS
        None.

        .OUTPUTS
        None. Does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Get-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Get-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE (If modules are already installed)
        PS> Get-ManagementCertificates -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000

        .LINK
        None
    #>

      param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck
        )


    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 2] Prepare to get management certificates in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }
    
    
     $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

     Write-Host "Subscription Name: [$($context.Subscription.Name)]"
     Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
     Write-Host "Account Name: [$($context.Account.Id)]"
     Write-Host "Account Type: [$($context.Account.Type)]"
     Write-Host $([Constants]::SingleDashLine)
    
    # To get the Resource URL from environment
    $ResourceAppIdURI = GetServiceManagementUrl

    # Using Get-AzAccessToken to get access token for fetching management certificates.
    $ClassicAccessToken= (Get-AzAccessToken -ResourceUrl $ResourceAppIdURI).Token
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 2] Fetching  management certificates in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if($null -ne $ClassicAccessToken)
    {
        $header = "Bearer " + $ClassicAccessToken
        $headers = @{"Authorization"=$header;"Content-Type"="application/json"; "x-ms-version" ="2013-08-01"}

        $uri = [string]::Format("{0}/{1}/certificates",$ResourceAppIdURI,$SubscriptionId)
        $mgmtCertsResponse = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -UseBasicParsing
        if($mgmtCertsResponse.StatusCode -ge 200 -and $mgmtCertsResponse.StatusCode -le 399)
        {
            if($null -ne $mgmtCertsResponse.Content)
            {
                [xml] $mgmtCerts = $mgmtCertsResponse.Content;
                if($null -ne $mgmtCerts -and [Helpers]::CheckMember($mgmtCerts, "SubscriptionCertificates.SubscriptionCertificate"))
                {
                    # Includes all the management certificates from the subscription
                    $ManagementCertificates = [ManagementCertificate]::ListManagementCertificates($mgmtCerts.SubscriptionCertificates.SubscriptionCertificate)
                
                    $context = Get-AzContext

                    if ([String]::IsNullOrWhiteSpace($context))
                    {
                    Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                    return
                    }
                    
                    $FolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\GetManagementCertificates"

                    if (-not (Test-Path -Path $FolderPath))
                    {
                       New-Item -ItemType Directory -Path $FolderPath | Out-Null
                    }

                    Write-Host "Storing Management Certificate details to [$($FolderPath)]..." -ForegroundColor $([Constants]::MessageType.Info)
                    $backupFile = "$($FolderPath)\GetManagementCertificates.csv"
                    $ManagementCertificates | Export-CSV -Path $backupFile -NoTypeInformation
                    Write-Host $([Constants]::SingleDashLine)
                    Write-Host "Management Certificates in a subscription have been saved to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)

                }
            }
        }
    }
}

function GetServiceManagementUrl
{
		$rmContext = [ContextHelper]::GetCurrentRMContext();
		$azureEnv= $rmContext.Environment.Name 
		if(-not [string]::IsNullOrWhiteSpace($azureEnv))
		{
		return [ContextHelper]::GetCurrentRMContext().Environment.ServiceManagementUrl
		}
		return "https://management.core.windows.net/"
}

class ManagementCertificate
{
	[string] $CertThumbprint
	[string] $SubjectName
	[string] $Issuer
	[PSObject] $Created
	[PSObject] $ExpiryDate
	[string] $IsExpired
	[PSObject] $Difference	
	[bool] $Whitelisted

	hidden static [ManagementCertificate[]] ListManagementCertificates([PSObject] $certObjects)
	{
		[ManagementCertificate[]] $certs = @()
		$certObjects | ForEach-Object{               
							[ManagementCertificate] $certObject = [ManagementCertificate]::new();
							$b64cert = $_.SubscriptionCertificateData                               
                            $certData = [System.Convert]::FromBase64String($b64Cert)                                                                      
                            $certX = [System.Security.Cryptography.X509Certificates.X509Certificate2]($certData)   
                            $certObject.ExpiryDate = $certX.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                            $certObject.CertThumbprint = $_.SubscriptionCertificateThumbprint
                            $certObject.SubjectName = $certX.Subject
                            $certObject.Issuer = $certX.Issuer
                            $certObject.Created = $_.Created
                            $certObject.IsExpired = "False"
                            $certObject.Difference = New-TimeSpan -Start ([datetime]$certX.NotBefore) -End ([datetime]$certX.NotAfter)
                            if([System.DateTime]::UtcNow -ge $certX.NotAfter)
                            {
                                $certObject.IsExpired = "True"
                            }
							#Has to be moved to new configuration model
							$certObject.Whitelisted = $false							
                            $certs += $certObject
                        }
		return $certs;
	}
}

class ContextHelper
{
 static hidden [PSObject] $currentRMContext;
        
    hidden static [PSObject] GetCurrentRMContext()
     {
        if (-not [ContextHelper]::currentRMContext)
        {
        $rmContext = Get-AzContext -ErrorAction Stop
            if ((-not $rmContext) -or ($rmContext -and (-not $rmContext.Subscription -or -not $rmContext.Account))) 
        {
            [PSObject]$rmLogin = $null
                
            $rmLogin = Connect-AzAccount
             
	        if ($rmLogin) 
            {
                $rmContext = $rmLogin.Context;	
	        }
        }
     [ContextHelper]::currentRMContext = $rmContext
        }
    return [ContextHelper]::currentRMContext
    }
}

class Helpers
{
    static [bool] CheckMember([PSObject] $refObject, [string] $memberPath)
	{
		return [Helpers]::CheckMember($refObject, $memberPath, $true);
	}

    static [bool] CheckMember([PSObject] $refObject, [string] $memberPath, [bool] $checkNull)
	{
        [bool]$result = $false;
        if ($refObject) {
            $properties = @();
            $properties += $memberPath.Split(".");

            if ($properties.Count -gt 0) {
                $currentItem = $properties.Get(0);
                if (-not [string]::IsNullOrWhiteSpace($currentItem)) {
                    if ($refObject | Get-Member -Name $currentItem)
					{
						if ($properties.Count -gt 1)
						{
							if($refObject.$currentItem)
							{
								$result = $true;
								$result = $result -and [Helpers]::CheckMember($refObject.$currentItem, [string]::Join(".", $properties[1..($properties.length - 1)]));
							}
						}
						else
						{
							if($checkNull)
							{
								if($refObject.$currentItem)
								{
									$result = $true;
								}
							}
							else
							{
								$result = $true;
							}
						}
                    }
                }
            }
        }
        return $result;
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








