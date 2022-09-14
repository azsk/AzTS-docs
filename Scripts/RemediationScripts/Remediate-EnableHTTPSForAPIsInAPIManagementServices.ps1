<###
# Overview:
    This script is used to enable HTTPS for all the APIs in the API Management Services in a Subscription..

# Control ID:
    Azure_APIManagement_DP_Use_HTTPS_URL_Scheme

# Display Name:
    "Ensure API Management service is accessible only over HTTPS".

# Prerequisites:
    Contributor and higher privileges on the API Management service in a Subscription.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of API Management Services in a Subscription that do not have HTTPS URL Scheme enabled for the API(s).
        3. Back up details of API Management Services that are to be remediated.
        4. Enable HTTPS URL Scheme on the API(s) in API Management Services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of API Management Services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable HTTPS URL Scheme on the API(s) in API Management Services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable HTTPS URL Scheme on the API(s) in API Management Services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable HTTPS URL Scheme on the API(s) in API Management Services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the API Management Services in a Subscription that will be remediated:
    
           Enable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To enable HTTPS URL Scheme on the API(s) in API Management Services in a Subscription:
       
           Enable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To enable HTTPS URL Scheme on the API(s) in API Management Services in a Subscription, from a previously taken snapshot:
       
           Enable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHttpsForApisInApiManagementServices\ApiManagementServicesWithoutHttpsEnabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-HttpsForApisInApiManagementServices -Detailed

    To roll back:
        1. To disable HTTPS URL Scheme on the API(s) in API Management Services in a Subscription, from a previously taken snapshot:
           Disable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHttpsForApisInApiManagementServices\RemediatedApiManagementServices.csv
        
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-HttpsForApisInApiManagementServices -Detailed        
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

function Enable-HttpsForApisInApiManagementServices
{
    <#
        .SYNOPSIS
        Remediates 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.

        .DESCRIPTION
        Remediates 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.
        Enables HTTPS URL Scheme on the API(s) in API Management Services in the Subscription. 
        
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

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Enable-HttpsForApisInApiManagementServices.

        .OUTPUTS
        None. Enable-HttpsForApisInApiManagementServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHttpsForApisInApiManagementServices\ApiManagementServicesWithoutHttpsEnabled.csv

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
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Prepare to enable HTTPS URL Scheme for API(s) in API Management Services in Subscription: [$($SubscriptionId)]"
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

    # Connect to Azure account.
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    if(-not $AutoRemediation)
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "This script can only be run by `User` Account Type. Account Type of [$($context.Account.Id)] is [$($context.Account.Type)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To enable HTTPS URL Scheme for API(s) in API Management Services in a Subscription, Contributor and higher privileges on the API Management Services are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 4] Fetch all API Management Services"
    Write-Host $([Constants]::SingleDashLine)

    $apiManagementResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_APIManagement_DP_Use_HTTPS_URL_Scheme"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "Error: File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all API Management services failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No API Management service(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $apiManagementResource = Get-AzAPIManagement -ResourceId $_.ResourceId -ErrorAction SilentlyContinue
                $apiManagementResources += $apiManagementResource
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                return
            }
        }
    }
    else 
    {
        # No file path provided as input to the script. Fetch all API Management Services in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all API Management Services in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            # Get all API Management Services in a Subscription
            $apiManagementResources = Get-AzAPIManagement -ErrorAction Stop
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            Write-Host "Fetching all API Management Services from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $apiManagementServicesDetails = Import-Csv -LiteralPath $FilePath
            $validApiManagementServicesDetails =  $apiManagementServicesDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            
            $validApiManagementServicesDetails | ForEach-Object {
                $resourceId = $_.ResourceId
            
                try
                {
                    $apiManagementResource = Get-AzAPIManagement -ResourceId $resourceId -ErrorAction SilentlyContinue
                    $apiManagementResources += $apiManagementResource
                }
                catch
                {
                    Write-Host "Error fetching API Management Service resource: Resource ID: [$($resourceId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this API Management Service resource..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }

    $totalApiManagementServices = ($apiManagementResources | Measure-Object).Count

    if ($totalApiManagementServices -eq 0)
    {
        Write-Host "No API Management service found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
  
    Write-Host "Found [$($totalApiManagementServices)] API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Includes API Management Services where HTTPS URL Scheme of API(s) is enabled.
    $apiManagementServicesWithHttpsEnabled = @()

    # Includes API Management Services where HTTPS URL Scheme of API(s) is not enabled.
    $apiManagementServicesWithoutHttpsEnabled = @()

    # Includes API Management Services that were skipped during remediation. There were errors remediating them.
    $apiManagementServicesSkipped = @()

    $apiManagementResources | ForEach-Object{ 
        $resourceId = $_.Id
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.Name

        $listOfApisWithoutHttpsEnabled = @()

        try
        {
            Write-Host "Fetching API Management Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Creating new context for API Management.
            $apiMgmtContext = New-AzAPIManagementContext -ResourceGroupName $ResourceGroupName -ServiceName $resourceName
            $apiMgmt = Get-AzAPIManagementAPI -Context $apiMgmtContext
            $apiMgmt | ForEach-Object{ 
                if($_.Protocols -contains "Http")
                {
                    $listOfApisWithoutHttpsEnabled += $_.Name      
                }
            }

            if($listOfApisWithoutHttpsEnabled.Count -eq 0)
            {
                $apiManagementServicesWithHttpsEnabled += $_
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","HTTPS URL Scheme of API(s) is already enabled in the API Management Service.")    
                $logSkippedResources += $logResource
            }
            else
            {   $listOfApisWithoutHttpsEnabled = $listOfApisWithoutHttpsEnabled -join ', '
                $apiManagementServicesWithoutHttpsEnabled+= $_ | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                    @{N='ResourceName';E={$resourceName}},
                                                                    @{N='ListOfAPIsWithoutHTTPSEnabled';E={$listOfApisWithoutHttpsEnabled}}
            }

            Write-Host "Successfully fetched the API Management Service configuration." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {   $listOfApisWithoutHttpsEnabled = $listOfApisWithoutHttpsEnabled -join ', '
            $apiManagementServicesSkipped += $_ | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='ResourceName';E={$resourceName}},
                                                                @{N='ListOfAPIsWithoutHTTPSEnabled';E={$listOfApisWithoutHttpsEnabled}}
            Write-Host "Error fetching API Management Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)

            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Error fetching API Management Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($_)]")    
            $logSkippedResources += $logResource
        }
    }

    $totalApiManagementServicesWithoutHttpsEnabled = ($apiManagementServicesWithoutHttpsEnabled| Measure-Object).Count

    if ($totalApiManagementServicesWithoutHttpsEnabled -eq 0)
    {
        Write-Host "No API Management service found with HTTPS URL Scheme not enabled for API(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation -and $totalApiManagementServices -gt 0)
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
        return
    }

    Write-Host "Found [$($totalApiManagementServicesWithoutHttpsEnabled)] API Management Service(s) to remediate." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableHttpsForApisInApiManagementServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up API Management Services details"
    Write-Host $([Constants]::SingleDashLine)
    # Backing up API Management Services details.
    $backupFile = "$($backupFolderPath)\ApiManagementServicesWithoutHttpsEnabled.csv"

    $apiManagementServicesWithoutHttpsEnabled| Export-CSV -Path $backupFile -NoTypeInformation
    Write-Host "API Management Services details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    if (-not $DryRun)
    {
        Write-Host "HTTPS URL Scheme will be enabled on the API(s) of API Management Services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to enable HTTPS URL Scheme on the API(s) of all API Management Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "HTTPS URL Scheme will not be enabled for any API(s) of API Management Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                Write-Host "User has provided consent to enable HTTPS URL Schema on the API(s) of all API Management Services." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. HTTPS URL Scheme will be enabled on the API(s) of all API Management Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host "[Step 4 of 4] Enable HTTPS URL Scheme for API(s) in API Management Services"
        Write-Host $([Constants]::SingleDashLine)

        # To hold results from the remediation.
        $apiManagementServicesRemediated = @()
        $apiManagementServicesSkipped = @()

        $apiManagementServicesWithoutHttpsEnabled| ForEach-Object {
            $apiManagementService = $_
            $resourceGroupName = $_.ResourceGroupName
           
            Write-Host "Enabling HTTPS URL Scheme for API(s) in API Management Service: Resource ID: [$($_.ResourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            
            try
            {   #To hold name of API(s) which are remediated and skipped.        
                $listOfApisRemediated = @()
                $listOfApisSkipped = @()

                $listOfApisRemediatedStr = [String]::Empty
                $listOfApisSkippedStr = [String]::Empty
                
                $apiMgmtContext = New-AzAPIManagementContext -ResourceGroupName $resourceGroupName -ServiceName $_.ResourceName
                $apiMgmt = Get-AzAPIManagementAPI -Context $apiMgmtContext
                $apiManagementService.ListOfAPIsWithoutHttpsEnabled = $apiManagementService.ListOfAPIsWithoutHttpsEnabled -split ', '
                $apiMgmt | ForEach-Object { 
                    if($apiManagementService.ListOfAPIsWithoutHttpsEnabled -contains  $_.Name)
                    {
                        Set-AzAPIManagementAPI -Context $apiMgmtContext -APIId $_.APIId -Protocols @("https") -ErrorAction SilentlyContinue
                        $output = (Get-AzAPIManagementAPI -Context $apiMgmtContext -APIId $_.APIId  -ErrorAction SilentlyContinue).Protocols 
                   
                        if ($output.count -eq 1 -and $output -eq "https")
                        {
                           $listOfApisRemediated += $_.Name
                        }
                        else
                        {
                            $listOfApisSkipped += $_.Name
                        }
                    }
                }  

                if($($listOfApisRemediated | Measure-Object).Count -gt 0)
                {
                    $listOfApisRemediatedStr = $($listOfApisRemediated -join ', ')
                    $apiManagementServicesRemediated += $apiManagementService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                            @{N='ResourceName';E={$_.ResourceName}},
                                                                                            @{N='ListOfAPIsRemediated';E={$listOfApisRemediatedStr}}
                    Write-Host "Successfully enabled HTTPS URL Schema for the APIs of the API Management Service: [$($listOfApisRemediatedStr)]" -ForegroundColor $([Constants]::MessageType.Update)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                    Write-Host ([Constants]::SingleDashLine)
                }

                if($($listOfApisSkipped | Measure-Object).Count -gt 0)
                {
                    $listOfApisSkippedStr = $($listOfApisSkipped -join ', ')
                    $apiManagementServicesSkipped += $apiManagementService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                            @{N='ResourceName';E={$_.ResourceName}},
                                                                                            @{N='ListOfAPIsSkipped';E={$listOfApisSkippedStr}}
                                                                                                                                            
                    Write-Host "Unsuccessful in enabling HTTPS URL Schema for the APIs of the API Management Service: [$($listOfApisSkippedStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Unsuccessful in enabling HTTPS URL Schema for the APIs of the API Management Service: [$($listOfApisSkippedStr)]")
                    $logSkippedResources += $logResource
                    Write-Host ([Constants]::SingleDashLine)
                }    
            }
            catch
            {
                $listOfApisSkippedStr = $($listOfApisSkipped -join ', ')
                $apiManagementServicesSkipped += $apiManagementService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                                        @{N='ListOfAPIsSkipped';E={$listOfApisSkippedStr}}
                                                                                       
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Error enabling HTTPS URL Scheme on the APIs of the API Management Service. Error: [$($_)].")
                $logSkippedResources += $logResource
                Write-Host "Error enabling HTTPS URL Scheme on the APIs of the API Management Service. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this API Management Service. HTTPS URL Scheme will not be enabled." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                return
            }    
                
        }

        if (($apiManagementServicesRemediated | Measure-Object).Count -eq $totalApiManagementServicesWithoutHttpsEnabled)
        {
            Write-Host "HTTPS URL Scheme successfully enabled for API(s) in all [$($totalApiManagementServicesWithoutHttpsEnabled)] API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "HTTPS URL Scheme successfully enabled for API(s) in [$($($apiManagementServicesRemediated | Measure-Object).Count)] out of [$($totalApiManagementServicesWithoutHttpsEnabled)] API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }
        Write-Host $([Constants]::DoubleDashLine)
        
        if($AutoRemediation)
        {
            if ($($apiManagementServicesRemediated | Measure-Object).Count -gt 0)
            {
                $apiManagementServicesRemediatedFile = "$($backupFolderPath)\RemediatedApiManagementServices.csv"
                $apiManagementServicesRemediated | Export-CSV -Path $apiManagementServicesRemediatedFile -NoTypeInformation
                Write-Host "This information related to API Management Services, where HTTPS URL Scheme successfully enabled, has been saved to [$($apiManagementServicesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $apiManagementServicesSkippedFile = "$($backupFolderPath)\SkippedApiManagementServices.csv"
                $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
                Write-Host "This information related to API Management Services, where HTTPS URL Scheme not enabled, has been saved to [$($apiManagementServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($apiManagementServicesRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "HTTPS URL Scheme successfully enabled for the API(s) in following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $apiManagementServicesRemediated | Format-Table -Property ResourceGroupName , ResourceName , ListOfAPIsRemediated
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $apiManagementServicesRemediatedFile = "$($backupFolderPath)\RemediatedApiManagementServices.csv"
                $apiManagementServicesRemediated | Export-CSV -Path $apiManagementServicesRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($apiManagementServicesRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "`nError enabling HTTPS URL Scheme for the API(s) in following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $apiManagementServicesSkipped | Format-Table -Property ResourceGroupName , ResourceName ,ListOfAPIsSkipped
                Write-Host $([Constants]::SingleDashLine)

                # Write this to a file.
                $apiManagementServicesSkippedFile = "$($backupFolderPath)\SkippedApiManagementServices.csv"
                $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($apiManagementServicesSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        if($AutoRemediation)
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                    $logControl.RollbackFile = $apiManagementServicesRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else 
    {
        Write-Host "[Step 4 of 4] Enable HTTPS URL Scheme for API(s) in API Management Services"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Since DryRun switch specified. HTTPS URL scheme will not be enabled for API Management Services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Next Steps:`n" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to enable HTTPS URL Scheme for API(s) in all API Management Services listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
}

function Disable-HttpsForApisInApiManagementServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_APIManagement_DP_Use_HTTPS_URL_Scheme' Control.
        Disables HTTPS URL Scheme on the API(s) in API Management Services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-HttpsForApisInApiManagementServices.

        .OUTPUTS
        None. Disable-HttpsForApisInApiManagementServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-HttpsForApisInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHttpsForApisInApiManagementServices\RemediatedApiManagementServices.csv

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
    Write-Host "[Step 1 of 3] Prepare to disable HTTPS URL Scheme for API(s) in API Management Services in Subscription: [$($SubscriptionId)]"
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

    # Connect to Azure account.
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "This script can only be run by `User` Account Type. Account Type of [$($context.Account.Id)] is [$($context.Account.Type)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To disable HTTPS URL Scheme for API(s) in API Management Services in a Subscription, Contributor and higher privileges on the API Management Services are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 3] Fetch all API Management Services"
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    Write-Host "Fetching all API Management Services from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    #$validApiManagementServicesDetails = @()
    $apiManagementServicesDetails = Import-Csv -LiteralPath $FilePath
    $validApiManagementServicesDetails = $apiManagementServicesDetails | Where-Object{ ![String]::IsNullOrWhiteSpace($_.ResourceId) }
     
    $totalApiManagementServices = ($validApiManagementServicesDetails|Measure-Object).Count

    if ($totalApiManagementServices -eq 0)
    {
        Write-Host "No API Management Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    Write-Host "Found [$($totalApiManagementServices)] API Management Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableHttpsForApisInApiManagementServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "HTTPS URL Scheme will be disabled on the API(s) in all API Management service." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force)
    {
        Write-Host "Do you want to disable HTTPS URL Scheme for API(s) in all API Management Services?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)

        if($userInput -ne "Y")
        {
            Write-Host "HTTPS URL Scheme will not be disabled for API(s) in any API Management Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to disable HTTPS URL Scheme for API(s) in all API Management Services." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. HTTPS URL Scheme will be disabled on the API(s) in API Management Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 3] Disable HTTPS URL Scheme for API(s) in all API Management Services"
    Write-Host $([Constants]::SingleDashLine)

    # Includes API Management Services, to which, previously made changes were successfully rolled back.
    $apiManagementServicesRolledBack = @()

    # Includes API Management Services that were skipped during roll back. There were errors rolling back the changes made previously.
    $apiManagementServicesSkipped = @()


    $validApiManagementServicesDetails | ForEach-Object {
        $apiManagementService = $_
           
        Write-Host "Disabling HTTPS URL Scheme for API(s) in API Management Service: Resource ID: [$($_.ResourceId)], Resource Group Name: [$($_.ResourceGroupName)], Resource Name: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
            
        try
        {           
            $listOfApisRolledBack = @()
            $listOfApisSkipped = @()
            $apiMgmtContext = New-AzAPIManagementContext -ResourceGroupName $_.ResourceGroupName -ServiceName $_.ResourceName
            $apiMgmt = Get-AzAPIManagementAPI -Context $apiMgmtContext
            $apiManagementService.ListOfAPIsRemediated = $apiManagementService.ListOfAPIsRemediated -split ', '
            $apiMgmt | ForEach-Object {      
                if($apiManagementService.ListOfAPIsRemediated -contains  $_.Name)
                {
                    Set-AzAPIManagementAPI -Context $apiMgmtContext -APIId $_.APIId -Protocols @("Http") -ErrorAction SilentlyContinue
                    $output = (Get-AzAPIManagementAPI -Context $apiMgmtContext -APIId $_.APIId  -ErrorAction SilentlyContinue).Protocols 
                        
                    if ($output.count -eq 1 -and $output -eq "http")
                    {
                       
                        $listOfApisRolledBack += $_.Name
                    }
                    else
                    {
                        $listOfApisSkipped += $_.Name
                    }
                }
            } 

            if($listOfApisRolledBack.count -ne 0)
            {
                $listOfApisRolledBackStr = $listOfApisRolledBack -join ', '
                $apiManagementServicesRolledBack += $apiManagementService |Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                                        @{N='ListOfAPIsRolledBack';E={$listOfApisRolledBackStr}}
                Write-Host "Successfully rolled back following API(s) in the API Management Service: [$($listOfApisRolledBackStr)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if($listOfApisSkipped.count -ne 0)
            {
                $listOfApisSkippedStr = $listOfApisSkipped -join ', '
                $apiManagementServicesSkipped += $apiManagementService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                                        @{N='ListOfAPIsSkipped';E={$listOfApisSkippedStr}}
                Write-Host "Unsuccessful in rolling back following API(s) in the API Management Service: [$($listOfApisSkippedStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }        
        }
        catch
        {
            $listOfApisSkippedStr = $listOfApisSkipped -join ', '
            $apiManagementServicesSkipped += $apiManagementService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                                    @{N='ResourceName';E={$_ResourceName}},
                                                                                    @{N='ListOfAPIsSkipped';E={$listOfApisSkippedStr}}
            Write-Host "Error disabling HTTPS URL Scheme on the API Management service. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this API Management Service. HTTPS URL Scheme will not be enabled for any of the API(s) of this service." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            return
        }  
    }  

    if ($($apiManagementServicesRolledBack | Measure-Object).Count -gt 0 -or $($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($apiManagementServicesRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "HTTPS URL Scheme successfully disabled for the API(s) in following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $apiManagementServicesRolledBack | Format-Table -Property ResourceGroupName , ResourceName , ListOfAPIsRolledBack
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $apiManagementServiceRolledBackFile = "$($backupFolderPath)\RolledBackApiManagementServices.csv"
            $apiManagementServicesRolledBack | Export-CSV -Path $apiManagementServiceRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to [$($apiManagementServiceRolledBackFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error disabling HTTPS URL Scheme for the API(s) in following API Management Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $apiManagementServicesSkipped | Format-Table -Property ResourceGroupName , ResourceName , ListOfAPIsSkipped
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $apiManagementServicesSkippedFile = "$($backupFolderPath)\RollBackSkippedApiManagementServices.csv"
            $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($apiManagementServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
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
