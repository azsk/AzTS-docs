<###
# Overview:
    This script is used to configure only RBAC(Role based access control) API Access for Azure AI Search services in a Subscription.

# Control ID:
    Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only

# Display Name:
    Protect Azure AI Search Instances by only allowing RBAC API Access

# Prerequisites:
    1. Contributor or higher privileges on the Azure AI Search services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Azure AI Search services in a Subscription that doesn't have only RBAC(Role based access control) API Access.
        3. Back up details of Azure AI Search services that are to be remediated.
        4. Set only RBAC(Role based access control) API Access on the non-compliant Azure AI Search services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Azure AI Search services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Reset API access on the all Azure AI Search services in the Subscription from backed up data.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to configure only RBAC(Role based access control) API Access for Azure AI Search services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to configure API Access for Azure AI Search services in the Subscription. Refer `Examples`, below.
       
# Examples:
    To remediate:
        1. To review the Azure AI Search services in a Subscription that will be remediated:
           Configure-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To configure RBAC only API access for all Azure AI Search services in a Subscription:
           Configure-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To configure RBAC only API access for all Azure AI Search services in a Subscription, from a previously taken snapshot:
           Configure-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202404080431\AISearchAPIAccess\AISearchServicesWithoutRBACOnlyAPIAccess.csv

        4. To configure RBAC only API access for all Azure AI Search services in a Subscription without taking back up before actual remediation:
           Configure-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Configure-RBACAPIAccessOnly -Detailed

    To roll back:
        1. To reset API access for all Azure AI Search services in a Subscription, from a previously taken snapshot:
           Reset-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202404080338\AISearchAPIAccess\RemediatedAISearchserviceAPIAccess.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-RBACAPIAccessOnly -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Search")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "[$($_)] module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}

function Configure-RBACAPIAccessOnly
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only' Control.

        .DESCRIPTION
        Remediates 'Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only' Control.
        Protect Azure AI Search Instances by only allowing RBAC API Access 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Configure-RBACAPIAccessOnly 
{.

        .OUTPUTS
        None. Configure-RBACAPIAccessOnly does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Configure-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Configure-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Configure-RBACAPIAccessOnly -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202404080338\AISearchAPIAccess\RemediatedAISearchserviceAPIAccess.csv

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

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

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
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 5] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)            
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 5] Validate the user"
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
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
    

    if(-not($AutoRemediation))	
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To configure RBAC only API access control for Azure AI Search Services in a Subscription, Contributor or higher privileges on Azure AI Search Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 5] Fetch all Azure AI Search Services"
    Write-Host $([Constants]::SingleDashLine)
    $AISearchServices = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()
    
    # Control Id
    $controlIds = "Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Fetching all Azure AI Search services failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceName)}

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Azure AI Search services found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        } 

        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
                $service = Get-AzSearchService -Name $name -ResourceGroupName $resourceGroupName 
                $AISearchServices = $AISearchServices + $service
            }
            catch
            {
                Write-Host "Error while fetching Azure AI Search service from input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Error while fetching Azure AI Search service from input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all Azure AI Search services in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Azure AI Search services in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Azure AI Search services in the Subscription
            $AISearchServices = Get-AzResource -ResourceType "Microsoft.Search/searchServices" -ErrorAction SilentlyContinue
            $totalAISearchServiceResources = ($AISearchServices | Measure-Object).Count
        
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all Azure AI Search services from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $AISearchserviceResourcesFromFile = Import-Csv -LiteralPath $FilePath
            $validresources = $AISearchserviceResourcesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.Name)-and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName)}
    
            $validresources | ForEach-Object {
                $resourceGroupName = $_.ResourceGroupName        
                $name = $_.Name
                try
                {
                    $AISearchServices += (Get-AzSearchService -ResourceGroupName $resourceGroupName -Name $name -ErrorAction SilentlyContinue) 

                }
                catch
                {
                    Write-Host "Error fetching Azure AI Search service: [$($name)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Azure AI Search service..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }
    
    $totalAISearchServiceResources = ($AISearchServices | Measure-Object).Count

    if ($totalAISearchServiceResources -eq 0)
    {
        Write-Host "No Azure AI Search services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalAISearchServiceResources)] Azure AI Search services." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
 
    # Includes Azure AI Search services where API access is RBAC only 
    $AISearchServiceWithRBACOnlyAPIAccess= @()

    # Includes Azure AI Search services where API access is not set as RBAC only   
    $AISearchServiceWithoutRBACOnlyAPIAccess= @()

    # Includes Azure AI Search services that were skipped during remediation. There were errors remediating them.
    $AISearchServiceSkipped = @()

    Write-Host "[Step 3 of 5] Fetching Azure AI Search services for remediation..."
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Azure AI Search services for which API access is not set as RBAC only ..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $AISearchServices | ForEach-Object {  
            $resource = $_
            $_ = Get-AzSearchService -ResourceGroupName $_.ResourceGroupName -Name $_.Name
            $DisableLocalAuth = $_.DisableLocalAuth

            # AuthOptions need to be saved for rollback purpose
            # there are 3 modes available for API access control. If we need to rollback, we need to provide AuthOption as mandatory value
            $authOption= "ApiKeyOnly"
            if($_.AuthOptions.AadOrApiKey.AadAuthFailureMode -ne $null)
            {
                $authOption= "AadOrApiKey"
            }
            if($DisableLocalAuth -ne $true){
            $AISearchServiceWithoutRBACOnlyAPIAccess += $resource | Select-Object @{N='Name';E={$_.Name}},
                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                    @{N='DisableLocalAuth';E={$DisableLocalAuth}},
                                                    @{N='AuthOption';E={$authOption}}


           }
           else
           {
            $AISearchServiceWithRBACOnlyAPIAccess += $resource | Select-Object @{N='Name';E={$_.Name}},
                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                    @{N='DisableLocalAuth';E={$DisableLocalAuth}},
                                                    @{N='AuthOption';E={$authOption}}
           

            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.Name))
            $logResource.Add("Reason","API access is already RBAC only in Azure AI Search service.")    
            $logSkippedResources += $logResource
           }
        
    }

    $totalAISearchServiceWithoutRBACOnlyAPIAccess = ($AISearchServiceWithoutRBACOnlyAPIAccess | Measure-Object).Count
     
    if ($totalAISearchServiceWithoutRBACOnlyAPIAccess -eq 0)
    {
        Write-Host "No Azure AI Search service found where API access is not RBAC only.. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        
        if($AutoRemediation -and ($AISearchResources |Measure-Object).Count -gt 0) 
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

    Write-Host "Found [$($totalAISearchServiceWithoutRBACOnlyAPIAccess)] Azure AI Search services where API access is not RBAC only" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    if(-not($AutoRemediation))
    {
        Write-Host "Following Azure AI Search services will be remediated :" -ForegroundColor $([Constants]::MessageType.Info)
        $colsProperty =     @{Expression={$_.Name};Label="Name";Width=20;Alignment="left"},
                            @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                            @{Expression={$_.DisableLocalAuth};Label="DisableLocalAuth";Width=20;Alignment="left"},
                            @{Expression={$_.authOption};Label="Auth failure mode";Width=20;Alignment="left"}


        $AISearchServiceWithoutRBACOnlyAPIAccess | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AISearchAPIAccess"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 4 of 5] Backing up Azure AI Search service details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up Azure AI Search service details.
            $backupFile = "$($backupFolderPath)\AISearchServicesWithoutRBACOnlyAPIAccess.csv"
            $AISearchServiceWithoutRBACOnlyAPIAccess | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "Azure AI Search services details have been successfully backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
  
    
    if (-not $DryRun)
    {  
        # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {

            Write-Host "API access will be set as RBAC only on all Azure AI Search services listed for remediation." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            if (-not $Force)
            {
                Write-Host "Do you want to set RBAC only API Access for all Azure AI Search services? " -ForegroundColor $([Constants]::MessageType.Warning) 
                
                $userInput = Read-Host -Prompt "(Y|N)" 
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "API access will not be changed for any Azure AI Search services. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }
                else
                {
                    Write-Host "RBAC only API Access will be set for all Azure AI Search services." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. RBAC only API Access will be set for all Azure AI Search services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host "[Step 5 of 5] Configuring RBAC only API Access for Azure AI Search services.."
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $AISearchservicesRemediated = @()
        $AISearchservicesSkipped = @()
    
        # Remediate AI search service by setting RBAC Only as API access 
        $AISearchServiceWithoutRBACOnlyAPIAccess | ForEach-Object {
            $resource = $_
            $name = $_.Name;
            $resourceGroupName = $_.ResourceGroupName; 

            # Holds the list of Azure AI Search services where API access change is skipped
            
            try
            {   
                Write-Host "Setting RBAC only API access for Azure AI search services : [$name]." -ForegroundColor $([Constants]::MessageType.Warning)
                $res = Get-AzSearchService -ResourceGroupName $resourceGroupName -Name $name 
                $authOption= "ApiKeyOnly"
                if($null -ne $res.AuthOptions.AadOrApiKey.AadAuthFailureMode)
                {
                    $authOption= "AadOrApiKey"
                }
                Write-Host $([Constants]::SingleDashLine)
                $response = Set-AzSearchService -ResourceGroupName $resourceGroupName -Name $name -DisableLocalAuth $true 
                
                if ($response.DisableLocalAuth -ne $true)
                {
                    $AISearchservicesSkipped += $resource
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.Name))
                    $logResource.Add("Reason", "Error while setting RBAC only API access for Azure AI Search service")
                    $logSkippedResources += $logResource    
                }
                else
                {
                    $AISearchservicesRemediated += $resource | Select-Object @{N='Name';E={$name}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='DisableLocalAuthBeforeRemediation';E={$false}},
                                                                        @{N='DisableLocalAuthPostRemediation';E={$true}},
                                                                        @{N='AuthOption';E={$authOption}}


                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.name))
                    $logRemediatedResources += $logResource
 
                }
            }
            catch
            {
                $AISearchservicesSkipped += $resource
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.name))
                $logResource.Add("Reason", "Error while setting RBAC only API access for Azure AI Search service")
                $logSkippedResources += $logResource 
            }
        }

        $totalAISearchservicesRemediated = ($AISearchservicesRemediated | Measure-Object).Count
         

        if ($totalAISearchservicesRemediated -eq ($AISearchServiceWithoutRBACOnlyAPIAccess | Measure-Object).Count)
        {
            Write-Host "API access set as RBAC only for all Azure AI Search services" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "API access set as RBAC only for [$($totalAISearchservicesRemediated)] out of [$($totalAISearchServiceWithoutRBACOnlyAPIAccess)] Azure AI Search services " -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.Name};Label="Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                        @{Expression={$_.DisableLocalAuthBeforeRemediation};Label="DisableLocalAuth (Before Remediation)";Width=20;Alignment="left"},
                        @{Expression={$_.DisableLocalAuthPostRemediation};Label="DisableLocalAuth (After Remediation)";Width=20;Alignment="left"},
                        @{Expression={$_.AuthOption};Label="AuthOption(Before Remediation)";Width=20;Alignment="left"}
  
        if($AutoRemediation)
        {
            if ($($AISearchservicesRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $AISearchservicesRemediatedFile = "$($backupFolderPath)\RemediatedAISearchserviceAPIAccess.csv"
                $AISearchservicesRemediated| Export-CSV -Path $AISearchservicesRemediatedFile -NoTypeInformation
                Write-Host "The information related to Azure AI Seach service where API access is successfully updated has been saved to [$($AISearchservicesRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($AISearchServiceSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $AISearchServiceSkippedFile = "$($backupFolderPath)\SkippedAISearchserviceAPIAccess.csv"
                $AISearchServiceSkipped | Export-CSV -Path $AISearchServiceSkippedFile -NoTypeInformation
                Write-Host "The information related to Azure AI Search service where API access is not set as RBAC only has been saved to [$($AISearchServiceSkipped)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($AISearchservicesRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set API access as RBAC only for following Azure AI Search services in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $AISearchservicesRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $AISearchservicesRemediatedFile = "$($backupFolderPath)\RemediatedAISearchserviceAPIAccess.csv"
                $AISearchservicesRemediated| Export-CSV -Path $AISearchservicesRemediatedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($AISearchservicesRemediatedFile)]"
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($AISearchServiceSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error changing API access for following Azure AI Search services:" -ForegroundColor $([Constants]::MessageType.Error)
                $AISearchServiceSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Adding AISearchServiceSkipped to a file.
                $AISearchServiceSkippedFile = "$($backupFolderPath)\SkippedAISearchserviceAPIAccess.csv"
                $AISearchServiceSkipped | Export-CSV -Path $AISearchServiceSkippedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($AISearchServiceSkippedFile)]"
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
                    $logControl.RollbackFile = $AISearchservicesRemediatedFile
                }
            }
            
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 5 of 5] Setting RBAC only API access for Azure AI Search services"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to configure API access for all Azure AI search services listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Reset-APIAccess
{
     <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only' Control.
        Resets API Access for all Azure AI Search services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-APIAccess.

        .OUTPUTS
        None. Reset-APIAccess does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-APIAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202404080431\AISearchAPIAccess\AISearchServicesWithoutRBACOnlyAPIAccess.csv

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
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 4] Validate the user" 
        Write-Host $([Constants]::SingleDashLine) 
    }  

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        
        Write-Host "Connecting to Azure account..."
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        # Setting up context for the current Subscription.
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    }

    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To reset API access for Azure AI Search services in a Subscription, Contributor or higher privileges on the Azure AI Search Services are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch Azure AI Search services"
    Write-Host $([Constants]::SingleDashLine)
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Fetching all Azure AI Search services from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
       
    $AISearchServicesFromFile = Import-Csv -LiteralPath $FilePath
    $validAISearchServices = $AISearchServicesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.Name) }
    
    $resource = @()
    $resourceList = @()

    $validAISearchServices | ForEach-Object {
        $name = $_.Name
        $resourceGroupName = $_.ResourceGroupName
        $DisableLocalAuthPostRemediation = $_.DisableLocalAuthPostRemediation
        $DisableLocalAuthBeforeRemediation = $_.DisableLocalAuthBeforeRemediation
        $AuthOption = $_.AuthOption
        try
        {
            $resource = (Get-AzSearchService -Name $name  -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue) 
            $resourceList += $resource | Select-Object @{N='Name';E={$name}},
                                                            @{N='ResourceGroupName';E={$resourceGroupName}},
                                                            @{N='CurrentDisableLocalAuth';E={$DisableLocalAuthPostRemediation}},
                                                            @{N='PreviousDisableLocalAuth';E={$DisableLocalAuthBeforeRemediation}},
                                                            @{N='PreviousAuthOption';E={$AuthOption}}
                                                                
        }
        catch
        {
            Write-Host "Error fetching Azure AI Search service : [$($name)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this Azure AI Search service..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
        
    # Includes Azure AI Search service
    $AISearchservicesWithRBACOnlyAPIAccess= @()
 
    Write-Host "[Step 3 of 4] Fetching Azure AI Search services"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Azure AI Search service where API access is RBAC only..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $resourceList | ForEach-Object {
        $res = $_        
            if(($res.CurrentDisableLocalAuth -eq $true))
            {
                $AISearchservicesWithRBACOnlyAPIAccess += $res
            }
            else
            {
                Write-Host "Skipping Azure AI Search service $($res.Name)..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
    }

    $totalAISearchservicesWithRBACOnlyAPIAccess = ($AISearchservicesWithRBACOnlyAPIAccess | Measure-Object).Count
     
    if ($totalAISearchservicesWithRBACOnlyAPIAccess  -eq 0)
    {
        Write-Host "No Azure AI Search service found where API access need to be changed.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
    
    Write-Host "Found [$($totalAISearchservicesWithRBACOnlyAPIAccess)] Azure AI Search services" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ConfigureAPIAccess"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to reset API access for all Azure AI Search services" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "API access will not be reset for any of the Azure AI Search services. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. API access will be reset for all of the Azure AI Search services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }
 
    Write-Host "[Step 4 of 4] Resetting API access for Azure AI Search services"
    Write-Host $([Constants]::SingleDashLine)
    # Includes Azure AI Search services, to which, previously made changes were successfully rolled back.
    $AISearchservicesRolledBack = @()

    # Includes Azure AI Search services that were skipped during roll back. There were errors rolling back the changes made previously.
    $AISearchservicesSkipped = @()

   
     # Roll back by resetting API access
        $AISearchservicesWithRBACOnlyAPIAccess | ForEach-Object {
            $res = $_
            $Name = $_.Name
            $resourceGroupName = $_.ResourceGroupName
            $authOption = $_.PreviousAuthOption
           
            try
            {  
                
                Write-Host "Resetting API access for Azure AI Search service : [$Name]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)

                $response = Set-AzSearchService -ResourceGroupName $resourceGroupName -Name $name -DisableLocalAuth $false -AuthOption $authOption

                if ($response.DisableLocalAuth -ne $false)
                {
                    $AISearchservicesSkipped += $res
                       
                }
                else
                {
                    $AISearchservicesRolledBack += $res | Select-Object @{N='Name';E={$Name}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}}, 
                                                                        @{N='DisableLocalAuthBeforeRollback';E={$true}},
                                                                        @{N='DisableLocalAuthAfterRollback';E={$response.DisableLocalAuth}}
                }
            }
            catch
            {
                $AISearchservicesSkipped += $res
            }
       }
    
    $totalAISearchservicesRolledBack = ($AISearchservicesRolledBack | Measure-Object).Count

    if ($totalAISearchservicesRolledBack -eq $totalAISearchservicesWithoutRBACOnlyAPIAccess)
    {
        Write-Host "API access reset for all [$($totalAISearchservicesWithoutRBACOnlyAPIAccess)] Azure AI Search services." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "API access reset for [$($totalAISearchservicesRolledBack)] out of [$($totalAISearchservicesWithRBACOnlyAPIAccess)] Azure AI Search services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
    
    Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    
    $colsProperty = @{Expression={$_.Name};Label="Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resrouce Group";Width=20;Alignment="left"},
                    @{Expression={$_.DisableLocalAuthAfterRollback};Label="DisableLocalAuth After Rollback";Width=20;Alignment="left"},
                    @{Expression={$_.DisableLocalAuthBeforeRollback};Label="DisableLocalAuth Before Rollback";Width=20;Alignment="left"}
        

    if ($($AISearchservicesRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Reset API access completed for below Azure AI Search services" -ForegroundColor $([Constants]::MessageType.Update)
        $AISearchservicesRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $AISearchservicesRolledBackFile = "$($backupFolderPath)\RolledBackAISearchservices.csv"
        $AISearchservicesRolledBack| Export-CSV -Path $AISearchservicesRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to [$($AISearchservicesRolledBackFile)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($AISearchservicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error resetting API access for following Azure AI Search services:" -ForegroundColor $([Constants]::MessageType.Error)
        $AISearchservicesSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $AISearchservicesSkippedFile = "$($backupFolderPath)\RollbackSkippedAISearchServices.csv"
        $AISearchservicesSkipped | Export-CSV -Path $AISearchservicesSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($AISearchservicesSkippedFile)]"
        Write-Host $([Constants]::SingleDashLine)
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