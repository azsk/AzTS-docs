<###
# Overview:
    This script is used to enable HTTPS url scheme so Backend API(s) are only accessible over HTTPS url scheme via API Management service in a Subscription.

# Control ID:
    Azure_APIManagement_DP_Use_HTTPS_URL_Scheme

# Display Name:
    "Ensure Backend API(s) are only accessible over HTTPS via API Management service".

# Prerequisites:
    Contributor and higher privileges on the API Management service in a Subscription.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of API Management services in a Subscription that do not have HTTPS url scheme enabled for the API(s).
        3. Back up details of API Management services that are to be remediated.
        4. Enable HTTPS url scheme on the API(s) in API Management services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of API Management services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable HTTPS url scheme on the API(s) in API Management services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable HTTPS url scheme on the API(s) of API Management services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable HTTPS url scheme on the API(s) of API Management services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the API Management services in a Subscription that will be remediated:
    
           Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To enable HTTPS url scheme on the API(s) of API Management services in a Subscription:
       
           Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To enable HTTPS url scheme on the API(s) of API Management services in a Subscription, from a previously taken snapshot:
       
           Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSUrlSchemeForAPIsOfAPIManagementServices\APIManagementServicesWithoutHttpsEnabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -Detailed

    To roll back:
        1. To disable HTTPS url scheme on the API(s) of API Management services in a Subscription, from a previously taken snapshot:
           Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSUrlSchemeForAPIsOfAPIManagementServices\RemediatedAPIManagementServices.csv
        
        2. To disable HTTPS url scheme on the API(s) of API Management services in a Subscription, from a previously taken snapshot:
           Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSUrlSchemeForAPIsOfAPIManagementServices\RemediatedAPIManagementServices.csv

        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.APIManagement")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
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

function Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices
{
    <#
        .SYNOPSIS
        Remediates 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.

        .DESCRIPTION
        Remediates 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.
        Enables HTTPS url scheme on the API(s) of API Management services in the Subscription. 
        
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
        None. You cannot pipe objects to Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices.

        .OUTPUTS
        None. Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSUrlSchemeForAPIsOfAPIManagementServices\APIManagementServicesWithoutHttpsEnabled.csv

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
    Write-Host "[Step 1 of 4] Preparing to enable HTTPS url scheme for API(s) of API Management services in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To enable HTTPS url scheme for API(s) of API Management services in a Subscription, Contributor and higher privileges on the API Management services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all API Management services..."

    $apiManagementResources = @()

    # No file path provided as input to the script. Fetch all API Management services in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all API Management services in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all API Management services in a Subscription
        $apiManagementResources = Get-AzAPIManagement -ErrorAction Stop
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all API Management services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        $apiManagementServiceDetails = Import-Csv -LiteralPath $FilePath
        $validApiManagementServiceDetails = $apiManagementServiceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
        $validApiManagementServiceDetails | ForEach-Object {
            $resourceId = $_.ResourceId
            try
            {
                Write-Host "Fetching API Management Service resource: Resource ID - $($resourceId)"
                $apiManagementResource = Get-AzAPIManagement -ResourceId $resourceId -ErrorAction SilentlyContinue
                $apiManagementResources += $apiManagementResource
            }
            catch
            {
                Write-Host "Error fetching API Management Service resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this API Management Service resource..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }

    $totalAPIManagementResources = ($apiManagementResources | Measure-Object).Count

    if ($totalAPIManagementResources -eq 0)
    {
        Write-Host "No API Management service found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
  
    Write-Host "Found $($totalAPIManagementResources) API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Includes API Management services where HTTPS url scheme of API(s) is enabled.
    $apiManagementWithHttpsEnabled = @()

    # Includes API Management services where HTTPS url scheme of API(s) is not enabled.
    $apiManagementWithoutHttpsEnabled = @()

    # Includes API Management services that were skipped during remediation. There were errors remediating them.
    $apiManagementServicesSkipped = @()

    $apiManagementResources | ForEach-Object{ 
        $resourceId = $_.Id
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.Name

        $listOfApiWithDisabledHttps = @()

        try
        {
            Write-Host "Fetching API Management Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)"
            #Creating new context for API Management.
            $apiMgmtContext = New-AzAPIManagementContext -ResourceGroupName $_.ResourceGroupName -ServiceName $_.Name
            $apiMgmt = Get-AzAPIManagementAPI -Context $apiMgmtContext
            $apiMgmt | ForEach-Object{ 
                if($_.Protocols -contains "Http")
                {
               
                    $listOfApiWithDisabledHttps += $_.Name      
                }
            }

            if($listOfApiWithDisabledHttps.Length -eq 0)
            {
                $apiManagementWithHttpsEnabled += $_
            }
            else
            {   $listOfApiWithDisabledHttps = $listOfApiWithDisabledHttps -join ","
                $apiManagementWithoutHttpsEnabled += $_ | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                    @{N='ResourceName';E={$resourceName}},
                                                                    @{N='ListOfAPIWithDisabledHttps';E={$listOfApiWithDisabledHttps}}
            }
        }
        catch
        {   $listOfApiWithDisabledHttps = $listOfApiWithDisabledHttps -join ","
            $apiManagementServicesSkipped += $_ | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='ResourceName';E={$resourceName}},
                                                                @{N='ListOfAPIWithDisabledHttps';E={$listOfApiWithDisabledHttps}}
            Write-Host "Error fetching API Management Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    $totalAPIManagementResourcesWithoutHttpsEnabled = ($apiManagementWithoutHttpsEnabled | Measure-Object).Count

    if ($totalAPIManagementResourcesWithoutHttpsEnabled -eq 0)
    {
        Write-Host "No API Management service found with HTTPS url scheme not enabled for API(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalAPIManagementResourcesWithoutHttpsEnabled) API Management Service(s) to remediate." -ForegroundColor $([Constants]::MessageType.Update)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableHTTPSUrlSchemeForAPIsOfAPIManagementServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up API Management services details:"
    
    # Backing up API Management services details.
    $backupFile = "$($backupFolderPath)\APIManagementServicesWithoutHttpsEnabled.csv"

    $apiManagementWithoutHttpsEnabled | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {
        Write-Host "API Management services details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "HTTPS url scheme will be enabled on the API(s) of all API Management services." -ForegroundColor $([Constants]::MessageType.Warning)

        if (-not $Force)
        {
            Write-Host "Do you want to enable HTTPS url scheme on the API(s) of all API Management services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "HTTPS url scheme will not be enabled for any API(s) of API Management Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. HTTPS url scheme will be enabled on the API(s) of all API Management services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enabling HTTPS url scheme for API(s) of API Management services..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $apiManagementServicesRemediated = @()
        $apiManagementServicesSkipped = @()

        $apiManagementWithoutHttpsEnabled | ForEach-Object {
            $apiManagementservice = $_
            $resourceGroupName = $_.ResourceGroupName
           
            Write-Host "Enabling HTTPS url scheme for API(s) of API Management Service: Resource ID - $($_.ResourceId), Resource Group Name - $($_.ResourceGroupName), Resource Name - $($_.ResourceName)" -ForegroundColor $([Constants]::MessageType.Warning)
            
            try
            {   #To hold name of API(s) which are remediated and skipped.        
                $listOfApiRemediated = @()
                $listOfApiSkipped = @()
                
                $apiMgmtContext = New-AzAPIManagementContext -ResourceGroupName $_.ResourceGroupName -ServiceName $_.ResourceName
                $apiMgmt = Get-AzAPIManagementAPI -Context $apiMgmtContext
                $apiManagementservice.ListOfAPIWithDisabledHttps = $apiManagementservice.ListOfAPIWithDisabledHttps -split ","
                $apiMgmt | ForEach-Object { 
                    if($apiManagementservice.ListOfAPIWithDisabledHttps -contains  $_.Name)
                    {
                        Set-AzAPIManagementAPI -Context $apiMgmtContext -ApiId $_.ApiId -Protocols @("Https") -ErrorAction SilentlyContinue
                        $output = (Get-AzAPIManagementAPI -Context $apiMgmtContext -ApiId $_.ApiId  -ErrorAction SilentlyContinue).Protocols 
                   
                        if($output -eq "Https")
                        {
                       
                            $listOfApiRemediated += $_.Name
                        }
                        else
                        {
                            $listOfApiSkipped += $_.Name
                        }
                    }
                }  

                if($listOfApiRemediated.count -ne '0')
                {
                    $listOfApiRemediated = $listOfApiRemediated -join ","
                    $apiManagementServicesRemediated += $apiManagementservice |Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                            @{N='ResourceName';E={$_.ResourceName}},
                                                                                            @{N='ListOfAPIRemediated';E={$listOfApiRemediated}}
                }

                if($listOfApiSkipped.count -ne '0')
                {
                    $listOfApiSkipped = $listOfApiSkipped -join ","
                    $apiManagementServicesSkipped += $apiManagementservice | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                            @{N='ResourceName';E={$_.ResourceName}},
                                                                                            @{N='ListOfAPISkipped';E={$listOfApiSkipped}}
                }        
            }
            catch
            {
                $listOfApiSkipped = $listOfApiSkipped -join ","
                $apiManagementServicesSkipped += $apiManagementservice | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                        @{N='ResourceName';E={$resourceName}},
                                                                                        @{N='ListOfAPISkipped';E={$listOfApiSkipped}}
                Write-Host "Error enabling HTTPS url scheme on the API. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this API Management Service. HTTPS url scheme will not be enabled." -ForegroundColor $([Constants]::MessageType.Error)
                return
            }    
                
        }
        
        Write-Host $([Constants]::SingleDashLine)

        if (($apiManagementServicesRemediated | Measure-Object).Count -eq $totalAPIManagementResourcesWithoutHttpsEnabled)
        {
            Write-Host "HTTPS url scheme successfully enabled for API(s) of all $($totalAPIManagementResourcesWithoutHttpsEnabled) API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "HTTPS url scheme successfully enabled for API(s) of $($($apiManagementServicesRemediated | Measure-Object).Count) out of $($totalAPIManagementResourcesWithoutHttpsEnabled) API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($apiManagementServicesRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "HTTPS url scheme successfully enabled for the API(s) of following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $apiManagementServicesRemediated | Format-Table -Property ResourceGroupName , ResourceName , ListOfAPIRemediated
           
            # Write this to a file.
            $apiManagementServicesRemediatedFile = "$($backupFolderPath)\RemediatedAPIManagementServices.csv"
            $apiManagementServicesRemediated | Export-CSV -Path $apiManagementServicesRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($apiManagementServicesRemediatedFile)"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError enabling HTTPS url scheme for the API(s) of following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $apiManagementServicesSkipped | Format-Table -Property ResourceGroupName , ResourceName ,ListOfAPISkipped
        
            # Write this to a file.
            $apiManagementServicesSkippedFile = "$($backupFolderPath)\SkippedAPIManagementServices.csv"
            $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($apiManagementServicesSkippedFile)"
        }
    }
    else 
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] API Management services details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to enable HTTPS url scheme for API(s) of all API Management services listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }
}

function Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.
        Disables HTTPS url scheme on the API(s) of API Management services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices.

        .OUTPUTS
        None. Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSUrlSchemeForAPIsOfAPIManagementServices\RemediatedAPIManagementServices.csv

        .EXAMPLE
        PS> Disable-HTTPSUrlSchemeForAPIsOfAPIManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck  -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSUrlSchemeForAPIsOfAPIManagementServices\RemediatedAPIManagementServices.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage="Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 3] Preparing to disable HTTPS url scheme for API(s) of API Management services in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To disable HTTPS url scheme for API(s) of API Management services in a Subscription, Contributor and higher privileges on the API Management services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all API Management services..."
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all API Management services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
    $validAPIManagementServiceDetails = @()
    $apiManagementServiceDetails = Import-Csv -LiteralPath $FilePath
    $apiManagementServiceDetails | ForEach-Object{
        if( ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) )
        {
            $validAPIManagementServiceDetails += $_
        }
      }

    $totalAPIManagementResources = $($validAPIManagementServiceDetails.Count)

    if ($totalAPIManagementResources -eq 0)
    {
        Write-Host "No API Management services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalAPIManagementResources) API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableHTTPSUrlSchemeForAPIsOfAPIManagementServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "HTTPS url scheme will be disabled on the API(s) of all API Management service." -ForegroundColor $([Constants]::MessageType.Warning)
    
    if (-not $Force)
    {
        Write-Host "Do you want to disable HTTPS url scheme for API(s) of all API Management services?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "HTTPS url scheme will not be disabled for API(s) of any API Management Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. HTTPS url scheme will be disabled on the API(s) of API Management services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disabling HTTPS url scheme for API(s) of all API Management services..." -ForegroundColor $([Constants]::MessageType.Warning)

    # Includes API Management services, to which, previously made changes were successfully rolled back.
    $apiManagementServicesRolledBack = @()

    # Includes API Management services that were skipped during roll back. There were errors rolling back the changes made previously.
    $apiManagementServicesSkipped = @()


    $validAPIManagementServiceDetails | ForEach-Object {
        $apiManagementservice = $_
           
        Write-Host "Enabling HTTPS url scheme for API(s) of API Management Service: Resource ID - $($_.ResourceId), Resource Group Name - $($_.ResourceGroupName), Resource Name - $($_.ResourceName)" -ForegroundColor $([Constants]::MessageType.Warning)
            
        try
        {           
            $listOfApiRolledBack = @()
            $listOfApiSkipped = @()
            #$$apiManagementservice.ListOfAPIRemediated
            $apiMgmtContext = New-AzAPIManagementContext -ResourceGroupName $_.ResourceGroupName -ServiceName $_.ResourceName
            $apiMgmt = Get-AzAPIManagementAPI -Context $apiMgmtContext
            $apiManagementservice.ListOfAPIRemediated  = $apiManagementservice.ListOfAPIRemediated -split ","
            $apiMgmt | ForEach-Object {      
                if($apiManagementservice.ListOfAPIRemediated -contains  $_.Name)
                {
                    Set-AzAPIManagementAPI -Context $apiMgmtContext -ApiId $_.ApiId -Protocols @("Http") -ErrorAction SilentlyContinue
                    $output = (Get-AzAPIManagementAPI -Context $apiMgmtContext -ApiId $_.ApiId  -ErrorAction SilentlyContinue).Protocols 
                        
                    if($output -eq "Http")
                    {
                       
                        $listOfApiRolledBack += $_.Name
                    }
                    else
                    {
                        $listOfApiSkipped += $_.Name
                    }
                }
            } 

            if($listOfApiRolledBack.count -ne '0')
            {
                $listOfApiRolledBack = $listOfApiRolledBack -join ","
                $apiManagementServicesRolledBack += $apiManagementservice |Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                                        @{N='ListOfAPIRolledBack';E={$listOfApiRolledBack}}
            }

            if($listOfApiSkipped.count -ne '0')
            {
                $listOfApiSkipped = $listOfApiSkipped -join ","
                $apiManagementServicesSkipped += $apiManagementservice | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                                        @{N='ListOfAPISkipped';E={$listOfApiSkipped}}
            }        
        }
        catch
        {
            $listOfApiSkipped = $listOfApiSkipped -join ","
            $apiManagementServicesSkipped += $apiManagementservice | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                    @{N='ResourceName';E={$_ResourceName}},
                                                                                    @{N='ListOfAPISkipped';E={$listOfApiSkipped}}
            Write-Host "Error enabling HTTPS url scheme on the API Management service. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this API Management Service. HTTPS url scheme will not be enabled for any of the API(s) of this service." -ForegroundColor $([Constants]::MessageType.Error)
            return
        }  
    }  

    if ($($apiManagementServicesRolledBack | Measure-Object).Count -gt 0 -or $($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($apiManagementServicesRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "HTTPS url scheme successfully disabled for the API(s) of following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $apiManagementServicesRolledBack | Format-Table -Property ResourceGroupName , ResourceName , ListOfAPIRolledBack

            # Write this to a file.
            $apiManagementServiceRolledBackFile = "$($backupFolderPath)\RolledBackApiManagementServices.csv"
            $apiManagementServicesRolledBack | Export-CSV -Path $apiManagementServiceRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($apiManagementServiceRolledBackFile)"
        }

        if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError disabling HTTPS url scheme for the API(s) of following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $apiManagementServicesSkipped | Format-Table -Property ResourceGroupName , ResourceName , ListOfAPISkipped

            
            # Write this to a file.
            $apiManagementServicesSkippedFile = "$($backupFolderPath)\RollbackSkippedApiManagementServices.csv"
            $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($apiManagementServicesSkippedFile)"
        }
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
