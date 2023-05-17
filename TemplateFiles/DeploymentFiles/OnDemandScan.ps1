########### Load Common Functions And Classes ###############

function Start-AzSKTenantSecuritySolutionOnDemandScan
{
    <#
	.SYNOPSIS
	This command would help in installing Azure Tenant Security Solution in your subscription. 
	.DESCRIPTION
	This command will install an Azure Tenant Security Solution which runs security scan on subscription in a Tenant.
	Security scan results will be populated in Log Analytics workspace and Azure Storage account which is configured during installation.  
	
	.PARAMETER SubscriptionId
		Subscription id in which Azure Tenant Security Solution needs to be installed.
	.PARAMETER ScanHostRGName
		Name of ResourceGroup where setup resources will be created.

	#>
    param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription id in which Azure Tenant Security Solution needs to be installed.")]
        $SubscriptionId,

        [string]
		[Parameter(Mandatory = $true, HelpMessage="Name of ResourceGroup where setup resources will be created.")]
		$ScanHostRGName = "AzSK-AzTS-RG",

        [switch]
        $ForceFetch,

        [switch]
        [Parameter(Mandatory = $false,  HelpMessage="Switch to specify if AzTS setup is integrated to vnet or not.")]
        $EnableVnetIntegration

    )
    Begin
        {
            $currentContext = $null
            $contextHelper = [ContextHelper]::new()
            $currentContext = $contextHelper.SetContext($SubscriptionId)
            $resourceManagerUrl =  $currentContext.Environment.ResourceManagerUrl
            if(-not ($currentContext -and $resourceManagerUrl))
            {
                return;
            }
            . "$PSScriptRoot\TokenProvider.ps1"
        }
    Process
    {
        if(-not $EnableVnetIntegration)
        {
            $maFunctionApp = $null
            try
            {
                Write-Host $([ScannerConstants]::DoubleDashLine)
                Write-Host "Running Azure Tenant Security Solution...`n" -ForegroundColor Cyan
                Write-Host $([ScannerConstants]::OnDemandScanInstructionMsg ) -ForegroundColor Cyan
                Write-Host $([ScannerConstants]::OnDemandScanWarningMsg ) -ForegroundColor Yellow
                Write-Host $([ScannerConstants]::SingleDashLine)

                $StartTimeAsString = [Datetime]::UtcNow.ToString("MM/dd/yyyy")

                $maFunctionApp = Get-AzWebApp -ResourceGroupName $ScanHostRGName | Where-Object { $_.Name -match "MetadataAggregator"} | Select -First 1
                $applicationInsight = Get-AzApplicationInsights -ResourceGroupName $ScanHostRGName | Where-Object { $_.Name -match "AzSK-AzTS-AppInsights"} | Select -First 1
                $laWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ScanHostRGName | Where-Object { $_.Name -match "AzSK-AzTS-LAWorkspace"} | Select -First 1

                if(($maFunctionApp -ne $null) -and ($applicationInsight -ne $null) -and ($laWorkspace -ne $null))
                {
                    if($ForceFetch)
                    {
                        Write-Host "[WARNING] Enabling forceFetch for [$($maFunctionApp.Name)] function app." -ForegroundColor Yellow
                        $StartTimeAsString = [Datetime]::UtcNow.ToString("MM/dd/yyyy, HH:mm:ss")
                        $maFunctionAppSlot = Get-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $maFunctionApp.Name -Slot 'production'
                        $appSettings = $maFunctionAppSlot.SiteConfig.AppSettings
                        #setup the current app settings
                        $settings = @{}
                        ForEach ($isetting in $appSettings) {
                            $settings[$isetting.Name] = $isetting.Value
                        }

                        $settings['WebJobConfigurations__ForceFetch'] = $true.ToString().Tolower()
                        $updatedSlotDetails = Set-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $maFunctionApp.Name -Slot 'production' -AppSettings $settings;
                    }
                    
                    $functionAppHostName  =  "https://" + $maFunctionApp.DefaultHostName;
                    $functionAppKeys = GetFunctionAppKey -AppServiceResourceId $maFunctionApp.Id
                    $functionAppMaterKey = $functionAppKeys.masterKey;
                    $laWorkspaceId = $laWorkspace.CustomerId.Guid
                    TriggerFunction -FunctionAppHostName $functionAppHostName -FunctionName $([ScannerConstants]::FunctionApp.SubscriptionInvProcessor) -FunctionAppMaterKey $functionAppMaterKey
                    TriggerFunction -FunctionAppHostName $functionAppHostName -FunctionName  $([ScannerConstants]::FunctionApp.BaselineControlsInvProcessor) -FunctionAppMaterKey $functionAppMaterKey
                    WaitForFunctionToComplete -StartTimeAsString $StartTimeAsString -FunctionName $([ScannerConstants]::FunctionApp.SubscriptionInvProcessor) -ApplicationInsightId $applicationInsight.Id -LAWorkspaceId $laWorkspaceId
                    WaitForFunctionToComplete -StartTimeAsString $StartTimeAsString -FunctionName $([ScannerConstants]::FunctionApp.BaselineControlsInvProcessor) -ApplicationInsightId $applicationInsight.Id -LAWorkspaceId $laWorkspaceId                

                    TriggerFunction -FunctionAppHostName $functionAppHostName -FunctionName $([ScannerConstants]::FunctionApp.SubscriptionRBACProcessor) -FunctionAppMaterKey $functionAppMaterKey
                    WaitForFunctionToComplete -StartTimeAsString $StartTimeAsString -FunctionName $([ScannerConstants]::FunctionApp.SubscriptionRBACProcessor) -ApplicationInsightId $applicationInsight.Id  -LAWorkspaceId $laWorkspaceId
                    
                    TriggerFunction -FunctionAppHostName $functionAppHostName -FunctionName $([ScannerConstants]::FunctionApp.WorkItemScheduler) -FunctionAppMaterKey $functionAppMaterKey
                    WaitForFunctionToComplete -StartTimeAsString $StartTimeAsString -FunctionName $([ScannerConstants]::FunctionApp.WorkItemScheduler) -ApplicationInsightId $applicationInsight.Id  -LAWorkspaceId $laWorkspaceId

                    Write-Host "$([Constants]::DoubleDashLine)" #-ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host "$([ScannerConstants]::NextStepsMsg)" -ForegroundColor Cyan
                    Write-Host "$([Constants]::DoubleDashLine)"

                }
                else
                {
                    Write-Host "Error occurred while triggering on-demand scan. ErrorMessage [MetadataAggregator function app, Application Insight or Log Analytics workspace not found.]" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch
            {
                Write-Host "Error occurred while triggering AzTS scan. ExceptionMessage [$($_)]"
            }
            finally
            {
                if($ForceFetch -and $maFunctionApp -ne $null)
                {
                    Write-Host "[WARNING] Disabling forceFetch for [$($maFunctionApp.Name)] function app." -ForegroundColor Yellow
                    $maFunctionAppSlot = Get-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $maFunctionApp.Name -Slot 'production'
                    $appSettings = $maFunctionAppSlot.SiteConfig.AppSettings
                    #setup the current app settings
                    $settings = @{}
                    ForEach ($isetting in $appSettings) {
                        $settings[$isetting.Name] = $isetting.Value
                    }

                    $settings['WebJobConfigurations__ForceFetch'] = $false.ToString().Tolower()
                    $updatedSlotDetails = Set-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $maFunctionApp.Name -Slot 'production' -AppSettings $settings;
                }
            }
        }
        else 
        {

            $StorageAccount = $null
            $queueName = "ondemandprocessingqueue"
            try
            {
                Write-Host $([ScannerConstants]::DoubleDashLine)
                Write-Host "Running Azure Tenant Security Solution...`n" -ForegroundColor Cyan
                Write-Host $([ScannerConstants]::QueueInstructionMsg ) -ForegroundColor Cyan
                Write-Host $([ScannerConstants]::ClientIpInstructionMsg ) -ForegroundColor Yellow

                $ClientIpAdditionFlag = Read-Host -Prompt "Allow addition of client IP to AzTS storage account (Y/N)"
                if($ClientIpAdditionFlag -eq 'Y')
                {
                    while([string]::IsNullOrWhiteSpace($clientIPAddress))
                    {
                        $clientIPAddress = Read-Host -Prompt "`nPlease provide client IP address "
                    }
                }
                else
                {
                    Write-Host "`n Terminated command execution for Client IP addition." -ForegroundColor Cyan
                    Write-Host $([ScannerConstants]::DoubleDashLine)
                    break;
                }

                Write-Host $([ScannerConstants]::SingleDashLine)

                if($SubscriptionId -ne $null -and $ScanHostRGName -ne $null)
                {
                    $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ScanHostRGName | Where-Object { $_.StorageAccountName -match "azskaztsstorage"} | Select -First 1
                }
                else
                {
                    throw [System.ArgumentException] ("Unable to fetch storage account details. Please check if you have access to host RG");
                }

                    
                #Adding client ip to storage
                Write-Host "Adding client IP to AzTS storage account [$($StorageAccount.StorageAccountName)], this may take 1-2 mins. `n" -ForegroundColor Yellow

                $IpAddedToStorage = Add-AzStorageAccountNetworkRule -ResourceGroupName $ScanHostRGName -AccountName $storageAccount.StorageAccountName -IPAddressOrRange $clientIPAddress

                if(-not $IpAddedToStorage)
                {
                    throw [System.ArgumentException] ("Error occurred while adding client IP to storage account.");
                }
                
                Start-Sleep -Seconds 30 # waiting for 30 sec for IP to be successfully added  in storage account
                Write-Host "Successfully added client IP [$($clientIPAddress)] to AzTS storage account [$($StorageAccount.StorageAccountName)]. `n" -ForegroundColor Cyan

                #fetching storage account access keys
                $storageAccountKey = Get-AzStorageAccountKey -ResourceGroupName $ScanHostRGName -Name $storageAccount.StorageAccountName -ErrorAction Stop  

                if(-not $storageAccountKey)
                {
                    throw [System.ArgumentException] ("Unable to fetch 'storageAccountKey'. Please check if you have the access to read storage key.");
                }
                else
                {
                    $storageAccountKey = $storageAccountKey.Value[0]
                }

                $storageContext = New-AzStorageContext -StorageAccountName $storageAccount.StorageAccountName  -StorageAccountKey $storageAccountKey -ErrorAction Stop

                #check if queue exists, else create new
                if($queueName -ne $null)
                {
                        $queue = Get-AzStorageQueue –Name $queueName –Context $storageContext -ErrorAction SilentlyContinue
                        if(-not $queue)
                        {   
                            $queue = New-AzStorageQueue -Name $queueName -Context $storageContext -ErrorAction Stop
                        }
                }

                #add message to the queue 
                $queueMessage = [Microsoft.Azure.Storage.Queue.CloudQueueMessage]::new("{""AzTSHostsubscriptionId"":""$($SubscriptionId)"", ""AzTSHostResourceGroup"":""$($ScanHostRGName)""}");

                if($queueMessage -ne $null)
                {
                    $message = $queue.CloudQueue.AddMessageAsync($queueMessage)
                    Write-Host "Successfully added message to AzTS storage account [$($StorageAccount.StorageAccountName)] for initiating on demand processing. `n" -ForegroundColor Cyan
                }
                else
                {
                    throw [System.ArgumentException] ("Unable to add message to queue."); 
                }

                #removing client IP from storage 
                $removedIp = Remove-AzStorageAccountNetworkRule -ResourceGroupName $ScanHostRGName -AccountName $storageAccount.StorageAccountName -IPAddressOrRange $clientIPAddress 
                Write-Host "Removed client IP [$($clientIPAddress)] from AzTS storage account [$($StorageAccount.StorageAccountName)]." -ForegroundColor Cyan 

                Write-Host "$([Constants]::DoubleDashLine)" 
                Write-Host "$([ScannerConstants]::NextStepsMsg)" -ForegroundColor Cyan
                Write-Host "$([Constants]::DoubleDashLine)"

            }
            catch
            {
                Write-Host "Error occurred while adding client IP to storage account. Please make sure you have provided correct IP address and you have proper permissions (at least Contributor) on host RG and subscription. ExceptionMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            }
            finally
            {
                if($ClientIpAdditionFlag -eq 'Y')
                {
                    $IpAddList = (Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $ScanHostRGName -AccountName $storageAccount.StorageAccountName).IPRules
                    if($clientIPAddress -in $IpAddList.IPAddressOrRange)
                    {
                        $removedIp = Remove-AzStorageAccountNetworkRule -ResourceGroupName $ScanHostRGName -AccountName $storageAccount.StorageAccountName -IPAddressOrRange $clientIPAddress 
                    }
                }
            }
        }
    }
}

function WaitForFunctionToComplete
{
    param (
        [ValidateNotNullOrEmpty()] 
        [string] $FunctionName,

        [ValidateNotNullOrEmpty()] 
        [string] $StartTimeAsString,

        [ValidateNotNullOrEmpty()] 
        [string] $ApplicationInsightId,

        [ValidateNotNullOrEmpty()] 
        [string] $LAWorkspaceId
    )

    $FunctionAppStatus = [EventStatus]::NotCompleted
    $LAStatus =  [EventStatus]::NotCompleted
    Write-Host "Waiting for [$($FunctionName)] function to complete its job." -ForegroundColor Yellow
    Write-Host "This operation can take up to 15 minutes (approx)." -NoNewline -ForegroundColor Yellow
    @(1..15) | ForEach-Object {
            $FunctionAppStatus = EventProcessor -StartTimeAsString $StartTimeAsString -FunctionName $FunctionName -ApplicationInsightId $ApplicationInsightId                
            $LAStatus = LogAnalyticsEventProcessor -StartTimeAsString $StartTimeAsString -FunctionName $FunctionName -WorkspaceId $LAWorkspaceId                
            if($FunctionAppStatus -ne [EventStatus]::Completed)
            {
                Write-Host ..$($_) -NoNewline -ForegroundColor Yellow;
                Start-Sleep -Seconds 60
            }
            elseif($LAStatus -ne [EventStatus]::Completed)
            {
               Write-Host ..$($_) -NoNewline -ForegroundColor Yellow;
               Start-Sleep -Seconds 60
            }
            else
            {
                # No Action
            }
     }

      Write-Host ""
    if($FunctionAppStatus -eq [EventStatus]::Completed -and $LAStatus -eq [EventStatus]::Completed)
    {
        Write-Host "[$($FunctionName)] completed proccessing." -ForegroundColor Cyan
    }
    else
    {
         Write-Host "Exceeded max wait time. [$($FunctionName)] is taking longer than expected to process. Continue to the next step." -ForegroundColor Cyan
    }
}

function GetFunctionAppKey
{

    param (
        [ValidateNotNullOrEmpty()] 
        [string] $AppServiceResourceId
    )

   try
   {
        if ($resourceManagerUrl)
        {
            $functionAppListKeyURL = $resourceManagerUrl + $AppServiceResourceId + "/host/default/listkeys?api-version=2018-11-01"

            $headers = [TokenProvider]::new().GetAuthHeader($resourceManagerUrl);
        }
        $functionAppKeysResponse = Invoke-WebRequest -UseBasicParsing -Uri $functionAppListKeyURL -Method Post -Headers $headers -Body '{}'
        
        $functionAppKeys =  $functionAppKeysResponse.Content | ConvertFrom-Json
        return $functionAppKeys
   }
   catch
   {
        throw $_
   }
}


function TriggerFunction
{
    
    param (
        [ValidateNotNullOrEmpty()] 
        [string] $FunctionName,

        [ValidateNotNullOrEmpty()] 
        [string] $FunctionAppHostName,

        [ValidateNotNullOrEmpty()] 
        [string] $FunctionAppMaterKey
    )

    $maxRetryCount = 3
    $retryCount = 0

    try
    {
        while($retryCount -lt $maxRetryCount)
        {
            try
            {
                $baseFunctionAppTriggerURL = $FunctionAppHostName + "/admin/functions/{0}";
                $functionAppTriggerURL = ([string]::Format($baseFunctionAppTriggerURL, $FunctionName));
                
                Write-Host "Starting [$($FunctionName)] function." -ForegroundColor Cyan
                $response = Invoke-WebRequest -UseBasicParsing -Uri $functionAppTriggerURL -Method Post -Headers @{ "x-functions-key" = "$($FunctionAppMaterKey)";"Content-Type"="application/json" } -Body '{}'
                Write-Host "Successfully triggered [$($FunctionName)] function." -ForegroundColor Cyan 
                $retryCount = $maxRetryCount
            }
            catch
            {
                $retryCount += 1;
                if ($retryCount -ge $maxRetryCount)
                {
                    throw $($_);
                }
                else
                {
                    Start-Sleep -Seconds (30 * $retryCount)
                }
            }
        }# WhileEnd 
    }
    catch
    {
        Write-Host "Error occurred while triggering function app [$($FunctionName)] ExceptionMessage [$($_)]. Please validate that the function is in running state and run this command again." -ForegroundColor Red
    }
}

function EventProcessor
{
    param(
        [ValidateNotNullOrEmpty()] 
        [string] $StartTimeAsString,

        [ValidateNotNullOrEmpty()] 
        [string] $FunctionName,

        [ValidateNotNullOrEmpty()] 
        [string] $ApplicationInsightId
    )
    
     $Status = [EventStatus]::NotCompleted

     try 
     {
        if ($resourceManagerUrl)
        {
           $aiQueryAPI = $resourceManagerUrl + $ApplicationInsightId + "/query?api-version=2018-04-20&query=traces
           | where customDimensions.LogLevel contains 'Information'
           | where timestamp > todatetime('{0}') 
           | where customDimensions.Category contains '{1}' and customDimensions.EventId == 2001
           | project StatusId = customDimensions.EventId" -f $StartTimeAsString, $FunctionName
   
           $headers = [TokenProvider]::new().GetAuthHeader($resourceManagerUrl);
        }
        $response = Invoke-WebRequest -UseBasicParsing -Uri $aiQueryAPI -Method Get -Headers $headers 
   
        if($response -ne $null)
        {
           $customObject = $response.Content | ConvertFrom-Json
   
           if(($customObject | GM tables) -and ($customObject.tables -ne $null) -and ($customObject.tables[0] | GM rows) -and ($customObject.tables[0].rows -ne $null))
           {
               $Status = [EventStatus]::Completed
           }
        }
     }
     catch
     {
        throw $_
     }

     return $Status;
}


function LogAnalyticsEventProcessor
{
    param(
        [ValidateNotNullOrEmpty()] 
        [string] $StartTimeAsString,

        [ValidateNotNullOrEmpty()] 
        [string] $FunctionName,

        [ValidateNotNullOrEmpty()] 
        [string] $WorkspaceId
    )
    
     $Status = [EventStatus]::NotCompleted

     try
     {
        $LAQuery = [string]::Empty

        switch($FunctionName)
        {
             $([ScannerConstants]::FunctionApp.SubscriptionInvProcessor) { $LAQuery = $([ScannerConstants]::SubscriptionInvLAQuery -f $StartTimeAsString) }
             $([ScannerConstants]::FunctionApp.BaselineControlsInvProcessor) { $LAQuery = $([ScannerConstants]::BaselineControlsInvLAQuery -f $StartTimeAsString) }
             $([ScannerConstants]::FunctionApp.SubscriptionRBACProcessor) { $LAQuery = $([ScannerConstants]::RBACInvLAQuery -f $StartTimeAsString) }
             $([ScannerConstants]::FunctionApp.WorkItemScheduler) { $LAQuery = $([ScannerConstants]::ControlResultsLAQuery -f $StartTimeAsString) }
        }
        
        if(![string]::IsNullOrWhiteSpace($LAQuery))
        {
            
            $Result  = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $LAQuery
            if(($Result.Results | Measure-Object).Count -gt 0)
            {
                $Status = [EventStatus]::Completed
            }

        }
     }
     catch
     {
        Write-Host "Error occurred while validating result in Log Analytics. ExceptionMessage [$($_.Exception.Message)]".
     }

     return $Status;
}

enum EventStatus
{
    NotCompleted
    Completed
}

class ScannerConstants
{
    static [string] $OnDemandScanInstructionMsg = "This command will perform 4 important operations. It will:`r`n`n" + 
					"   [1] Trigger subscription inventory processor `r`n" +
                    "   [2] Trigger baseline controls inventory processor `r`n" +
					"   [3] Trigger Role-Based Access Control (RBAC) processor `r`n" +
                    "   [4] Trigger work item scheduler `r`n";
    static [string] $OnDemandScanWarningMsg = "Please note that if the AzTS Soln has been setup recently, this command can take up to 30-45 minutes as it has to create tables in Log Analytics workspace for each inventory that is processed as part of this command.";
    static [string] $NextStepsMsg = "Subscriptions have been queued for scan. The scan result will be available in the next 2 hours.";

    static [string] $QueueInstructionMsg = "This command will perform below activities. It will:`r`n`n" + 
                    "   [1] Send on-demand processing request using storage queue. `r`n" +
                    "   [2] Using on-demand processing request, it will trigger below AzTS processing functions in sequence: `r`n" +
                        "            [a] Subscription inventory processor: Collects subscription list to be scanned `r`n" +
                        "            [b] Controls inventory processor: Collects control inventory `r`n" +
                        "            [c] Role-Based Access Control (RBAC) processor: Collects RBAC data `r`n" +
                        "            [d] WorkItem scheduler: Send subscription list from inventory to scanning queue `r`n" +
                    "   [3] WorkItemProccessor will get auto triggered based on scanning queue messages and will scan the controls. `r`n";

    static [string] $ClientIpInstructionMsg = "As your AzTS solution is integrated to VNet, i.e. resources like storage have access restrictions and firewall applied, therefore to trigger on-demand processing from your machine, we will need to add your client IP to AzTS storage account firewall (present inside host RG where your AzTS solution is hosted) on temporary basis. Once the message is added to the scanning queue, your IP will be removed from storage account. `r`n" ;

    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"

    static [string] $SubscriptionInvLAQuery = "let TablePlaceholder = view () {{print SubscriptionId = 'SubscriptionIdNotFound'}};
                                                      let SubInventory_CL = union isfuzzy=true TablePlaceholder, (union (
                                                      AzSK_SubInventory_CL | where TimeGenerated > todatetime('{0}')
                                                      | distinct SubscriptionId
                                                      ))
                                                      | where SubscriptionId !~ 'SubscriptionIdNotFound';
                                                      SubInventory_CL";
    static [string] $BaselineControlsInvLAQuery = "let TablePlaceholder = view () {{print ControlId_s = 'NA'}};
                                                          let BaselineControlsInv_CL = union isfuzzy=true TablePlaceholder, (union (
                                                          AzSK_BaselineControlsInv_CL | where TimeGenerated > todatetime('{0}')
                                                          | distinct ControlId_s
                                                          ))
                                                          | where ControlId_s !~ 'NA';
                                                          BaselineControlsInv_CL";
    static [string] $RBACInvLAQuery = "let TablePlaceholder = view () {{print NameId = 'NA', RoleId = 'NA'}};
                                              let RBAC_CL = union isfuzzy=true TablePlaceholder, (union (
                                              AzSK_RBAC_CL | where TimeGenerated > todatetime('{0}')
                                              | take 10
                                              | project RoleId = coalesce(RoleId_g, RoleId_s), NameId = NameId_g
                                              ))
                                              | where NameId !~ 'NA';
                                              RBAC_CL";
    static [string] $ControlResultsLAQuery = "let TablePlaceholder = view () {{print SubscriptionId = 'SubscriptionIdNotFound'}};
                                                     let ControlResults_CL = union isfuzzy=true TablePlaceholder, (union (
                                                     AzSK_ControlResults_CL | where TimeGenerated > todatetime('{0}')
                                                     | distinct SubscriptionId
                                                     ))
                                                     | where SubscriptionId !~ 'SubscriptionIdNotFound';
                                                     ControlResults_CL
                                                     | take 10";

    static [Hashtable] $FunctionApp = @{
            SubscriptionInvProcessor = 'ATS_01_SubscriptionInvProcessor'
            BaselineControlsInvProcessor = 'ATS_02_BaselineControlsInvProcessor'
            SubscriptionRBACProcessor = 'ATS_03_SubscriptionRBACProcessor'
            WorkItemScheduler = 'ATS_04_WorkItemScheduler'
    }

}