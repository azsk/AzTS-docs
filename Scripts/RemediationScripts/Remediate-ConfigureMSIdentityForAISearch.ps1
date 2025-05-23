
<##########################################

# Overview:
    This script ensures all Azure AI Search services in the subscription are configured to use Managed Service Identity (MSI) for authentication.

# ControlId: 
    Azure_AISearch_AuthN_Use_Managed_Service_Identity

# Pre-requisites:
    1. You will need Contributor or higher privileged role on Azure AI Search services.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Install and validate required modules for managing Azure AI Search services.
        2. Fetch all Azure AI Search services in the subscription and check their current MSI configuration.
        3. Update non-compliant Azure AI Search services to enable MSI.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Fetch the backup of original MSI configurations (if available).
        3. Restore the original MSI settings for Azure AI Search services from the backup.

# Step to execute script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate resource type in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback on all resource type in the Subscription. Refer `Examples`, below.

# Command to execute:
    To remediate:
        1. Run below command to configure MSI for all Azure AI Search services in the subscription:
           
            Set-MSIForAISearch  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
        
        To know more about parameter execute:
            Get-Help Set-MSIForAISearch  -Detailed
            
        To roll back:
        1. Run below command to roll back MSI configuration for Azure AI Search services in the subscription:
           
            Set-MSIForAISearch  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\AISearch\RemediatedResourceType.csv
        
        To know more about parameter execute:
   
            Get-Help Set-MSIForAISearch  -Detailed

########################################
#>


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

function Fetch-API {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Method,
        
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Body = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Headers = @{}
    )

    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessTokenSecure = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl -AsSecureString -WarningAction SilentlyContinue
    $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessTokenSecure.Token)
    )
    $authHeader = "Bearer " + $accessToken
    $Headers["Authorization"] = $authHeader
    $Headers["Content-Type"] = "application/json"

    try {
        switch ($Method.ToUpper()) {
            "GET" {
                $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            "POST" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method Post -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
            }
            "PUT" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method Put -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
            }
            "DELETE" {
                $response = Invoke-WebRequest -Uri $Uri -Method Delete -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            default {
                throw "Unsupported HTTP method: $Method"
            }
        }

        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
            return $response.Content | ConvertFrom-Json
        }
        else {
            throw "API call failed with status code $($response.StatusCode)"
        }
    }
    catch {
        Write-Error "Error occurred: $_"
    }
}


function Set-MSIForAISearch {
    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation")]
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user..."
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)    
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)    
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else {
        Write-Host "[Step 1 of 4] Validate the user..."
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "***To configure MSI on Azure AI Search services in a Subscription, Contributor or higher privileges are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Fetching all Azure AI Search services..."
    Write-Host $([Constants]::SingleDashLine)

     # To keep track of remediated and skipped resources
     $logRemediatedResources = @()
     $logSkippedResources = @()
     $searchServicesAPI = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Search/searchServices?api-version=2023-11-01"
 
     #Control id for the control
     $controlIds = "Azure_AISearch_AuthN_Use_Managed_Service_Identity"
 
     if($AutoRemediation)
     {
         if(-not (Test-Path -Path $Path))
         {
             Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
             Write-Host $([Constants]::SingleDashLine)
             return
         }
         Write-Host "Fetching all AI Search service(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
         Write-Host $([Constants]::SingleDashLine)
         $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
         $subId = $controlForRemediation.SubscriptionId
         $controls = $controlForRemediation.ControlRemediationList
         $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
         $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
         if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
         {
             Write-Host "No AI Search service(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
             Write-Host $([Constants]::SingleDashLine)
             return
         }
         $validResources | ForEach-Object { 
             try
             {
                 $AISearchResourceAPI = "https://management.azure.com/subscriptions/$subId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Search/searchServices/$($_.ResourceName)?api-version=2023-11-01" 
                 $AISearchDetail = Fetch-API -Method Get -Uri $AISearchResourceAPI -ErrorAction Stop
 
                 $AISearchDetails += $AISearchDetail | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                @{N='ResourceGroupName';E={($_.Id -split '/')[4]}},
                                                                @{N='ResourceName';E={$_.Name}},
                                                                @{N='ManagedServiceIdentity';E={$_.Properties.identity.type}},
                                                                @{N='Location';E={$_.Location}},
                                                                @{N='Sku';E={$_.Sku}}
             }
             catch
             {
                 Write-Host "Valid resource information not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                 Write-Host "Skipping the Resource: [$($_.ResourceName)]..."
                 $logResource = @{}
                 $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                 $logResource.Add("ResourceName",($_.ResourceName))
                 $logResource.Add("Reason","Valid ResourceName(s)/ResourceGroupName not found in input json file.")    
                 $logSkippedResources += $logResource
                 Write-Host $([Constants]::SingleDashLine)
             }
         }
     }
     else
     {
         # No file path provided as input to the script. Fetch all AI Search service(s) in the Subscription.
         if ([String]::IsNullOrWhiteSpace($FilePath))
         {
             try
             {
                 Write-Host "Fetching all AI Search service(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)
 
                 # Get all AI Search service(s) in a Subscription
                 $AISearchDetails = Fetch-API -Method Get -Uri $searchServicesAPI -ErrorAction Stop
 
                 # Seperating required properties
                 $AISearchDetails = $AISearchDetails.value | Select-Object @{N='ResourceId';E={$_.Id}}, 
                                                                @{N='ResourceGroupName';E={($_.Id -split '/')[4]}},                                                               
                                                                @{N='ResourceName';E={$_.Name}},
                                                                @{N='ManagedServiceIdentity';E={$_.identity.type}},
                                                                @{N='Location';E={$_.Location}},
                                                                @{N='Sku';E={$_.Sku}}
             }
             catch
             {
                 Write-Host "Error fetching AI Search service(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                 $logResource = @{}
                 $logResource.Add("SubscriptionID",($SubscriptionId))
                 $logResource.Add("Reason","Error fetching AI Search service(s) information from the subscription.")    
                 $logSkippedResources += $logResource
             }    
         }
         else
         {
             if (-not (Test-Path -Path $FilePath))
             {
                 Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                 break
             }
 
             Write-Host "Fetching all AI Search service(s) from [$($FilePath)]..." 
 
             $AISearchResources = Import-Csv -LiteralPath $FilePath
             $validAISearchResources = $AISearchResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
         
             $validAISearchbResources | ForEach-Object {
             $resourceId = $_.ResourceId
                 try
                 {
                     $AISearchResourceAPI = "https://management.azure.com/subscriptions/$subId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Search/searchServices/$($_.ResourceName)?api-version=2023-11-01" 
                     $AISearchDetail = Fetch-API -Method Get -Uri $AISearchResourceAPI -ErrorAction Stop
 
             
                     $AISearchDetails += $AISearchDetail | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                      @{N='ResourceGroupName';E={($_.Id -split '/')[4]}},
                                                                      @{N='ResourceName';E={$_.Name}},
                                                                      @{N='ManagedServiceIdentity';E={$_.identity.type}},
                                                                      @{N='Location';E={$_.Location}},
                                                                      @{N='Sku';E={$_.Sku}}
                 }
                 catch
                 {
                     Write-Host "Error fetching AI Search service(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                     $logResource = @{}                     
                     $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                     $logResource.Add("ResourceName",($_.ResourceName))
                     $logResource.Add("Reason","Error fetching AI Search service(s) information.")    
                     $logSkippedResources += $logResource
                 }
             }
         }

         $totalAISearch = ($AISearchDetails | Measure-Object).Count


         if ($totalAISearch -eq 0)
    {
        Write-Host "No AI Search service(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalAISearch)] AI Search service(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing AI Search service(s) where required Managed Service Identity (MSI) is not configured
    $NonCompliantMSIAISearch = @()

    Write-Host "Separating AI Search service(s) for which Managed Service Identity (MSI) is not configured..."

    $AISearchDetails | ForEach-Object {
        $AISearch = $_
        

        if((!$_.ManagedServiceIdentity -eq "SystemAssigned"))
        {
            $NonCompliantMSIAISearch += $AISearch
        }
        else
        {
            $logResource = @{}
            $logResource.Add("ResourceName",($_.ResourceName))
            if ($_.ManagedServiceIdentity -eq "SystemAssigned") {
                $logResource.Add("Reason","Managed Service Identity (MSI) configured set on AI Search service.")
            }  
            $logSkippedResources += $logResource
        }
    }

    $totalNonCompliantAISearch = ($NonCompliantMSIAISearch | Measure-Object).Count

    if ($totalNonCompliantAISearch -eq 0)
    {
        Write-Host "No AI Search service(s) found with non-compliant Managed Service Identity (MSI). Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantAISearch)] AI Search service(s) with non-compliant Managed Service Identity (MSI):" -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},                    
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.ManagedServiceIdentity};Label="ManagedServiceIdentity";Width=10;Alignment="left"}
        
    $NonCompliantMSIAISearch | Format-Table -Property $colsProperty -Wrap


    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\MSIForAISearch"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up AI Search service(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up AI Search service(s) details
        $backupFile = "$($backupFolderPath)\NonCompliantMSIAISearch.csv"

        $NonCompliantMSIAISearch | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "AI Search service(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
    
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non-compliant AI Search service(s)..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "This step will configure Managed Service Identity (MSI) for authentication for all non-compliant AI Search service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if($userInput -ne "Y")
                {
                    Write-Host "Managed Service Identity (MSI) will not be configured on AI Search service(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Managed Service Identity (MSI) will be configured on AI Search service(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # List for storing remediated AI Search service(s)
        $AISearchRemediated = @()

        # List for storing skipped AI Search service(s)
        $AISearchSkipped = @()

        $setAISearchUri 

        Write-Host "Configuring Managed Service Identity (MSI) on all listed AI Search service(s)." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)



        # Loop through the list of AI Search service(s) which needs to be remediated.
       
       $NonCompliantMSIAISearch | ForEach-Object {     
       
            $AISearch = $_
            $AISearch | Add-Member -NotePropertyName isMSIAISearchSetPostRemediation -NotePropertyValue $false
            $AISearch | Add-Member -NotePropertyName PreviousManagedServiceIdentity -NotePropertyValue $AISearch.ManagedServiceIdentity
       

            Write-Host "Configuring Managed Service Identity (MSI) on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)
            try
            {                

               $result= Set-AzSearchService -Name $_.ResourceName -ResourceGroupName $_.ResourceGroupName -IdentityType SystemAssigned

                if($result)
                {   
                    $AISearch.isMSIAISearchSetPostRemediation = $true
                    $AISearch | Add-Member -NotePropertyName CurrentManagedServiceIdentity -NotePropertyValue 'SystemAssigned'
                    $AISearchRemediated += $AISearch

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                    Write-Host "Successfully Configured the Managed Service Identity (MSI) on AI Search service [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
                else
                {   
                    $AISearch.isMSIAISearchSetPostRemediation = $false
                    $AISearchSkipped += $AISearch
                                     
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error occurred while Configuring the Managed Service Identity (MSI) on AI Search service.")
                    $logSkippedResources += $logResource
                    Write-Host "Skipping this AI Search service." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }  
            }
            catch
            {   
                $AISearchSkipped += $AISearch
                         
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error while Configuring the Managed Service Identity (MSI) on AI Search service.")
                $logSkippedResources += $logResource
                Write-Host "Skipping this AI Search service." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                                @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                                @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                                @{Expression={$_.CurrentManagedServiceIdentity};Label="CurrentManagedServiceIdentity";Width=10;Alignment="left"},
                                @{Expression={$_.PreviousMSIAISearch};Label="PreviousMSIAISearch";Width=10;Alignment="left"},
                                @{Expression={$_.isMSIAISearchSetPostRemediation};Label="isMSIAISearchSetPostRemediation";Width=10;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($AISearchRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Managed Service Identity (MSI) configured on the following AI Search service(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
        
            $AISearchRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $AISearchRemediatedFile = "$($backupFolderPath)\RemediatedAISearch.csv"
            $AISearchRemediated | Export-CSV -Path $AISearchRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AISearchRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

         if ($($AISearchSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error configuringManaged Service Identity (MSI) on the following AI Search service(s) in the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $AISearchSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $AISearchSkippedFile = "$($backupFolderPath)\SkippedAISearch.csv"
            $AISearchSkipped | Export-CSV -Path $AISearchSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($AISearchSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $AISearchRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }


    }


     }


}

function Reset-MSIForAISearch 
{

 <#
    .SYNOPSIS
    Rolls back remediation done for 'Azure_AISearch_AuthN_Use_Managed_Service_Identity' Control.

    .DESCRIPTION
    Rolls back remediation done for 'Azure_AISearch_AuthN_Use_Managed_Service_Identity' Control.
    Disables Managed Service Identity (MSI) for Azure AI Search services.

    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription that was previously remediated.

    .PARAMETER Force
    Specifies a forceful rollback without any prompts.

    .PARAMETER PerformPreReqCheck
    Specifies validation of prerequisites for the command.

    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the rollback.

    .INPUTS
    None. You cannot pipe objects to Reset-MSIForAISearch.

    .OUTPUTS
    None. Reset-MSIForAISearch does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Reset-MSIForAISearch -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\AISearch\RemediatedResources.csv

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

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else
    {
        Write-Host "[Step 1 of 3] Validating the user..." 
    }  


    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "*** To reset MSI on Azure AI Search services in a Subscription, Contributor or higher privileges are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Azure AI Search service(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Azure AI Search service(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $AISearchDetails = Import-Csv -LiteralPath $FilePath

    $validAISearchDetails = $AISearchDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalAISearch = $(($validAISearchDetails|Measure-Object).Count)

    if ($totalAISearch -eq 0)
    {
        Write-Host "No Azure AI Search service(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validAISearchDetails|Measure-Object).Count)] Azure AI Search service(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.CurrentManagedServiceIdentity};Label="ManagedServiceIdentity";Width=50;Alignment="left"},
                    @{Expression={$_.PreviousManagedServiceIdentity};Label="PreviousManagedServiceIdentity";Width=50;Alignment="left"},
                    @{Expression={$_.isMSIAISearchSetPostRemediation};Label="isMSIAISearchSetPostRemediation";Width=50;Alignment="left"}
        
    $validAISearchDetails | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RollbackMSIOnAISearch"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back Managed Service Identity (MSI) for all Azure AI Search service(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        Write-Host "Please note: This will not roll back Azure AI Search service(s) where previous Managed Service Identity (MSI) was default."  -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Do you want to continue roll back operation?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Managed Service Identity (MSI) will not be rolled back for any Azure AI Search service(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
    }
    else
    {
        Write-Host "'Force' flag is provided. Previous Managed Service Identity (MSI) will be configured on Azure AI Search service(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }


    # List for storing rolled back Azure AI Search service(s).
    $AISearchRolledBack = @()

    # List for storing skipped rolled back Azure AI Search service(s).
    $AISearchSkipped = @()

    # List for Azure AI Search service(s) where previous MSI was default
    $AISearchWithDefaultValue = @()

    Write-Host "Starting Roll back operation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validAISearchDetails | ForEach-Object {
        $AISearch = $_
        $AISearch | Add-Member -NotePropertyName isMSIAISearchRolledback -NotePropertyValue $false
        try
        {
            Write-Host "Rolling back Managed Service Identity (MSI) on Azure AI Search service(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)
            

            $Result = Set-AzSearchService -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -IdentityType None

            if($Result)
            {
                Write-Host "Succesfully rolled back Managed Service Identity (MSI) on Azure AI Search service(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $AISearch.PreviousManagedServiceIdentity = $_.CurrentManagedServiceIdentity
                $AISearch.ManagedServiceIdentity = $_.ManagedServiceIdentity
                $AISearch.isMSIAISearchSetPostRemediation = $_.isMSIAISearchSetPostRemediation
                $AISearch.CurrentManagedServiceIdentity= 'None'
                $AISearch.isMSIAISearchRolledback = $true
                $AISearchRolledBack += $AISearch    
            }
            else
            {
                $AISearch.isMSIAISearchRolledback = $false
                $AISearchSkipped += $AISearch
            }
        }
        catch
        {
            $AISearchSkipped += $AISearch
        }
    }


    $colsPropertyRollBack = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.ManagedServiceIdentity};Label="ManagedServiceIdentity";Width=50;Alignment="left"},
                    @{Expression={$_.CurrentManagedServiceIdentity};Label="PreviousManagedServiceIdentity";Width=50;Alignment="left"},
                    @{Expression={$_.isMSIAISearchRolledback};Label="isMSIAISearchRolledback";Width=50;Alignment="left"}
     
     if ($($AISearchRolledBack | Measure-Object).Count -gt 0 -or $($AISearchSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($AISearchRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Managed Service Identity (MSI) is rolled back successfully on following Azure AI Search service(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $AISearchRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap

            # Write this to a file.
            $AISearchRolledBackFile = "$($backupFolderPath)\RolledBackAISearch.csv"
            $AISearchRolledBack | Export-CSV -Path $AISearchRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AISearchRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($AISearchSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error configuring Managed Service Identity (MSI) on following Azure AI Search service(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $AISearchSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $AISearchSkippedFile = "$($backupFolderPath)\RollbackSkippedAISearch.csv"
            $AISearchSkipped | Export-CSV -Path $AISearchSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AISearchSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)

            Write-Host "Note: MSI settings for [$($AISearchWithDefaultValue.count)] out of total count [$($validAISearchDetails.count)] is not configured for Azure AI Search service(s) because Managed Service Identity (MSI) was previously set to default." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

}


# Defines commonly used constants.
class Constants {
    # Defines commonly used colour codes, corresponding to the severity of the log...
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "=" * 120
    static [String] $SingleDashLine = "-" * 120
}