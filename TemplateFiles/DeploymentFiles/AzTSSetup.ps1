# Load all other scripts that are required by this script.
. "$PSScriptRoot\OnDemandScan.ps1"

# Standard configuration

$AzureEnvironmentAppServiceURI = @{
    "AzureCloud" = "https://{0}.azurewebsites.net";
    "AzureGovernmentCloud" = "https://{0}.azurewebsites.us";
}

function Install-AzSKTenantSecuritySolution
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
	.PARAMETER Location
		Location where all resources will get created. Default location is EastUS2.
	.PARAMETER ScanIdentityId
		Resource id of user managed identity used to scan subscriptions. 
    .PARAMETER TemplateFilePath
        Azure ARM template path used to deploy Azure Tenant Security Solution.
    .PARAMETER TemplateParameters
        Azure ARM template parameters used to deploy Azure Tenant Security Solution.
    .PARAMETER SendUsageTelemetry
        Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features."
    .PARAMETER EnableCentralVisibility
        Switch to enable central visibility of AzTS scan logs.
    .PARAMETER CentralStorageAccountConnectionString
        Connection string of the storage account to be used to store the scan logs centrally.
    .NOTES
	

	.LINK
	https://aka.ms/azts-docs

	#>
    Param(
        
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which Azure Tenant Security Solution needs to be installed.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Subscription id in which Azure Tenant Security Solution needs to be installed.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Subscription id in which Azure Tenant Security Solution needs to be installed.")]
        $SubscriptionId,

        [string]
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Name of ResourceGroup where setup resources will be created.")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="Name of ResourceGroup where setup resources will be created.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Name of ResourceGroup where setup resources will be created.")]
		$ScanHostRGName = "AzSK-AzTS-RG",

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default",  HelpMessage="Location where all resources will get created. Default location is EastUS2.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI",  HelpMessage="Location where all resources will get created. Default location is EastUS2.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility",  HelpMessage="Location where all resources will get created. Default location is EastUS2.")]
        $Location,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Resource id of user managed identity used to scan subscriptions.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Resource id of user managed identity used to scan subscriptions.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Resource id of user managed identity used to scan subscriptions.")]
        $ScanIdentityId,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility")]
        $TemplateFilePath = ".\AzTSDeploymentTemplate.json",

        [Hashtable]
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility")]
        $TemplateParameters = @{},

        [switch]
        [Parameter(Mandatory = $false,  ParameterSetName = "Default", HelpMessage="Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.")]
        [Parameter(Mandatory = $false,  ParameterSetName = "AzTSUI", HelpMessage="Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.")]
        [Parameter(Mandatory = $false,  ParameterSetName = "CentralVisibility", HelpMessage="Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.")]
        $SendUsageTelemetry = $false,

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Specify if user managed identity has Graph permission. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="Specify if user managed identity has Graph permission. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Specify if user managed identity has Graph permission. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        $ScanIdentityHasGraphPermission = $false,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Application (client) id of the Azure AD application to be used by API.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Application (client) id of the Azure AD application to be used by API.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Application (client) id of the Azure AD application to be used by API.")]
        $WebAPIAzureADAppId,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Application (client) id of the Azure AD application to be used by UI.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Application (client) id of the Azure AD application to be used by UI.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Application (client) id of the Azure AD application to be used by UI.")]
        $UIAzureADAppId,

        [string[]]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Email ids to which alert notification should be sent.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Email ids to which alert notification should be sent.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Email ids to which alert notification should be sent.")]
        $SendAlertNotificationToEmailIds = @(),

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [ValidateSet("AzureCloud", "AzureGovernmentCloud")]
        $AzureEnvironmentName = "AzureCloud",

        [switch]
        [Parameter(Mandatory = $false, HelpMessage="Switch to enable vnet integration. Resources required for vnet setup will be deployed only if this switch is ON.")]
        $EnableVnetIntegration = $false,

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Switch to enable AzTS auto updater. Autoupdater helps to get latest feature released for AzTS components covering updates for security controls. If this is disabled, you can manually update AzTS components by re-running setup command.")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="Switch to enable AzTS auto updater. Autoupdater helps to get latest feature released for AzTS components covering updates for security controls. If this is disabled, you can manually update AzTS components by re-running setup command.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Switch to enable AzTS auto updater. Autoupdater helps to get latest feature released for AzTS components covering updates for security controls. If this is disabled, you can manually update AzTS components by re-running setup command.")]
        $EnableAutoUpdater,

        [switch]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan.")]
        $EnableAzTSUI,

        [switch]
        [Parameter(Mandatory = $false, HelpMessage="Switch to enable WAF. Resources required for implementing WAF will be deployed only if this switch is ON.")]
        $EnableWAF = $false,
        
        [switch]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Switch to enable central visibility of AzTS scan logs.")]
        $EnableCentralVisibility = $false,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Connection string of the storage account to be used to store the scan logs centrally.")]
        $CentralStorageAccountConnectionString
    )
        Begin
        {
            $currentContext = $null
            $contextHelper = [ContextHelper]::new()
            $currentContext = $contextHelper.SetContext($SubscriptionId)
            if(-not $currentContext)
            {
                return;
            }
        }

        Process
        {
            $deploymentResult = $null;
            $UIUrl = [string]::Empty;
            $FunctionApps = $null;
            $AppServiceSlots = @();

            # flag to decide whether to prompt user for telemetry acceptance
            [bool] $PromptUserAcceptance = $true
            # Check if Auto Updater is already present.
            try
            {
                [string] $OnboardingTenant = [String]::Empty;
                [string] $OnboardingOrg = [String]::Empty;
                [string] $OnboardingDiv = [String]::Empty;
                [string] $OnboardingContactEmail = [String]::Empty;
                [string] $AnonymousUsageTelemetryLogLevel = [String]::Empty;

                $ResourceId='/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId,$ScanHostRGName;
                $ResourceIdHash = get-hash($ResourceId)
                $ResourceHash = $ResourceIdHash.Substring(0,5).ToString().ToLower()
                $AutoUpdaterName = "AzSK-AzTS-AutoUpdater-" + $ResourceHash
                $au = Get-AzWebApp -Name $AutoUpdaterName -ResourceGroupName $ScanHostRGName -ErrorAction SilentlyContinue
                #If Auto updater is not present then user will be prompted for telemetry acceptance.
                if($au)
                {                    

                    $au.SiteConfig.AppSettings | foreach {
                        if($_.Name -eq "AIConfigurations__AnonymousUsageTelemetry__LogLevel")
                        {
                            $AnonymousUsageTelemetryLogLevel = $_.Value;
                        }
                        if($_.Name -eq "OnboardingDetails__Organization")
                        {
                            $OnboardingOrg = $_.Value;
                        }
                        if($_.Name -eq "OnboardingDetails__Division")
                        {
                            $OnboardingDiv = $_.Value;
                        }
                        if($_.Name -eq "OnboardingDetails__ContactEmailAddressList")
                        {
                            $OnboardingContactEmail = $_.Value;
                        }
                        if($_.Name -eq "OnboardingDetails__TenantId")
                        {
                            $OnboardingTenant = $_.Value;
                        }
                    }

                    if([String]::IsNullOrWhiteSpace($AnonymousUsageTelemetryLogLevel)`
                    -or [String]::IsNullOrWhiteSpace($OnboardingOrg)`
                    -or [String]::IsNullOrWhiteSpace($OnboardingDiv)`
                    -or [String]::IsNullOrWhiteSpace($OnboardingContactEmail)`
                    -or [String]::IsNullOrWhiteSpace($OnboardingTenant))
                    {
                        $PromptUserAcceptance = $true
                    }
                    else
                    {
                        $PromptUserAcceptance = $false
                        $TemplateParameters.Add("AnonymousUsageTelemetryLogLevel", $AnonymousUsageTelemetryLogLevel)
                        $TemplateParameters.Add("OrganizationName", $OnboardingOrg)
                        $TemplateParameters.Add("DivisionName", $OnboardingDiv)
                        $TemplateParameters.Add("ContactEmailAddressList", $OnboardingContactEmail)
                        $TemplateParameters.Add("HashedTenantId", $OnboardingTenant)
                    }
        
                }
            }
            catch
            {
                $PromptUserAcceptance = $true
            }

           
            try
            {
                if($PromptUserAcceptance)
                {               
                    # Take acceptance from the user for the telemetry to be collected
                    [string] $TelemetryAcceptanceMsg = "For the purpose of improving quality of AzTS features and better customer service, the AzTS solution needs to collect the below mentioned data :`r`n`n" + 
                    "   [1] Anonymized AzTS usage data -> this helps us improve product quality`r`n" +
                    "   [2] Organization/team contact details -> these help us provide your team with:`r`n" +
                    "                            [a] Updates about AzTS feature change`r`n" +
                    "                            [b] Support channel options (e.g., office hours)`r`n" +
                    "                            [c] Occasional requests for feedback on specific features`r`n" +
                    "You may choose to opt in or opt out of either or both of these by choosing Y/N at the prompts coming up. (Note that you can change your choice later too.)`r`n"

                Write-Host $TelemetryAcceptanceMsg -ForegroundColor $([Constants]::MessageType.warning)
                

                $AnonymousUsageCaptureFlag = Read-Host -Prompt "`n`rAllow collection of anonymized usage data (Y/N)"
                $ContactDataCaptureFlag = Read-Host -Prompt "`n`Provide org/team contact info (Y/N)"
                if($ContactDataCaptureFlag -eq 'Y')
                {
                    # Capturing Onboarding details is enabled
                    if($AnonymousUsageCaptureFlag -eq 'Y')
                    {
                        # Capturing anonymous usage data is enabled
                        $TemplateParameters.Add("AnonymousUsageTelemetryLogLevel", "All")
                    }
                    else
                    {
                        # Capturing anonymous usage data is disabled
                        $TemplateParameters.Add("AnonymousUsageTelemetryLogLevel", "Onboarding")
                    }

                    Write-Host "`n`rPlease provide details about your org, divison and team." -ForegroundColor $([Constants]::MessageType.warning)
                    $OrganizationName = Read-Host -Prompt "Organization Name "
                    $TemplateParameters.Add("OrganizationName", $OrganizationName)
                    $DivisionName = Read-Host -Prompt "Division Name within your Organization "
                    $TemplateParameters.Add("DivisionName", $DivisionName)
                    $ContactEmailAddressList = Read-Host -Prompt "Contact DL to use for our communication "
                    $TemplateParameters.Add("ContactEmailAddressList", $ContactEmailAddressList)

                }
                else
                {
                    # Capturing Onboarding details is disabled
                    if($AnonymousUsageCaptureFlag -eq 'Y')
                    {
                        # Capturing anonymous usage data is enabled
                        $TemplateParameters.Add("AnonymousUsageTelemetryLogLevel", "Anonymous")
                    }
                    else
                    {
                        # Capturing anonymous usage data is disabled
                        $TemplateParameters.Add("AnonymousUsageTelemetryLogLevel", "None")
                    }
                }

                    Write-Host "`n`rThank you for your choices. To make changes to these preferences refer the FAQs by visiting https://aka.ms/AzTS-docs/UpdateTelemetryPreference." -ForegroundColor $([Constants]::MessageType.Update)
                }
                
            }
            catch
            {
                #silently continue with installation.
            }

            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Running Azure Tenant Security Solution setup...`n" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::InstallSolutionInstructionMsg ) -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            
            
            Write-Host "`r`nStarted setting up Azure Tenant Security Solution. This may take 5 mins..." -ForegroundColor $([Constants]::MessageType.Info)
           
            # Create resource group if not exist
            try
            {
                Write-Verbose "$(Get-TimeStamp)Checking resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                $rg = Get-AzResourceGroup -Name $ScanHostRGName -ErrorAction SilentlyContinue
                if(-not $rg)
                {
                    Write-Verbose "$(Get-TimeStamp)Creating resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                    $rg = New-AzResourceGroup -Name $ScanHostRGName -Location $Location -ErrorAction Stop
                }
                else{
                    Write-Verbose "$(Get-TimeStamp)Resource group already exists." #-ForegroundColor $([Constants]::MessageType.Info)
                }
                
            }
            catch
            {  
                Write-Host "`n`rFailed to create resource group for deployment." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }
                        
	        # start arm template deployment
            try
            {

                # Set EnableVnetIntegration value based on switch selected by user
                if($EnableVnetIntegration)
                {
                    $TemplateParameters.Add("EnableVnetIntegration", $true)
                }
                else
                {
                    $TemplateParameters.Add("EnableVnetIntegration", $false)
                }

                 # Set EnableWAF value based on switch selected by user
                 if($EnableWAF)
                 {
                     $TemplateParameters.Add("EnableWAF", $true)
                 }
                 else
                 {
                     $TemplateParameters.Add("EnableWAF", $false)
                 }
 
                 # set frontdoor and web app endpoint suffixf
                 if($AzureEnvironmentName -eq 'AzureGovernmentCloud')
                 {
                     $TemplateParameters.Add("FrontDoorEndpointSuffix", ".azurefd.us")
                     $TemplateParameters.Add("WebAppEndpointSuffix", ".azurewebsites.us")
                 }
                 else 
                 {
                     $TemplateParameters.Add("FrontDoorEndpointSuffix", ".azurefd.net")
                     $TemplateParameters.Add("WebAppEndpointSuffix", ".azurewebsites.net")
                 }

                # Select rule based on graph permission.
                if($ScanIdentityHasGraphPermission)
                {
                    $TemplateParameters.Add("RuleEngineWorkflowName", "FullTenantScan")
                    $TemplateParameters.Add("IsGraphFeatureEnabled", "true")
                }
                else
                {
                    $TemplateParameters.Add("RuleEngineWorkflowName", "FullTenantScanExcludeGraph")
                    $TemplateParameters.Add("IsGraphFeatureEnabled", "false")
                }

                $TemplateParameters.Add("AzureEnvironmentName", $AzureEnvironmentName)
                $TemplateParameters.Add("EnableCentralVisibility", $EnableCentralVisibility.IsPresent)
                $TemplateParameters.Add("CentralStorageAccountConnectionString", $CentralStorageAccountConnectionString)

                # Get package version
                

                $CentralPackageInfo = [CentralPackageInfo]::new()

                $TemplateParameters.Add("MetadataAggregatorPackageURL", $CentralPackageInfo.MetadataAggregatorPackageURL)
                $TemplateParameters.Add("WorkItemProcessorPackageURL", $CentralPackageInfo.WorkItemProcessorPackageURL)
                $TemplateParameters.Add("WebApiPackageURL", $CentralPackageInfo.WebApiPackageURL)
                $TemplateParameters.Add("UIPackageURL", $CentralPackageInfo.UIPackageURL)

                # if($TemplateParameters.Count -eq 0)
                # {
                #     Write-Host "`n`rPlease enter the parameter required for template deployment:" -ForegroundColor $([Constants]::MessageType.Info)   
                #     Write-Host "Note: Alternatively you can use '-TemplateParameters' to pass these parameters.`n`r"  -ForegroundColor $([Constants]::MessageType.Warning)   
                # }
                $ResourceId='/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId,$ScanHostRGName;
                $ResourceIdHash = get-hash($ResourceId)
                $ResourceHash = $ResourceIdHash.Substring(0,5).ToString().ToLower() #considering only first 5 characters
                $TelemetryIdentifier = $ResourceIdHash.Substring(0,16).ToString().ToLower()

                #adding ResourceHash to TemplateParameters
                $TemplateParameters.Add("TelemetryIdentifier", $TelemetryIdentifier)
                $TemplateParameters.Add("ResourceHash", $ResourceHash)
                $TemplateParameters.Add("MIResourceId", $ScanIdentityId)
                
                #Enable autoupdater template parameter
                if($EnableAutoUpdater)
                {
                    $TemplateParameters.Add("IsAutoUpdaterEnabled", $true)
                }
                else
                {
                    $TemplateParameters.Add("IsAutoUpdaterEnabled", $false)
                }

                 #Enable AzTSUI template parameter
                 if($EnableAzTSUI)
                 {
                     $TemplateParameters.Add("IsAzTSUIEnabled", $true)
                 }
                 else
                 {
                     $TemplateParameters.Add("IsAzTSUIEnabled", $false)
                 }

                #Get the tenant Id from the current subscription contex
                $context=Get-AzContext
                $TemplateParameters.Add("TenantId", $context.Tenant.Id)
                # We also collect hashed TenantId as part of on boarding details
                if($PromptUserAcceptance)
                {
                    $HashedTenantId = get-hash($context.Tenant.Id)
                    $TemplateParameters.Add("HashedTenantId", $HashedTenantId)
                }
            

                # Creating Azure AD application: Web API
                $TemplateParameters.Add("WebApiClientId", $WebAPIAzureADAppId)
                $TemplateParameters.Add("UIClientId", $UIAzureADAppId)


                #updating UI app settings for already existing UI, this will require deletion of pre-existing UI and re-deploying it with updated settings.
                $ResourceId='/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId,$ScanHostRGName;
                $ResourceIdHash = get-hash($ResourceId)
                $ResourceHash = $ResourceIdHash.Substring(0,5).ToString().ToLower()
                $UIName = "AzSK-AzTS-UI-" + $ResourceHash
                #getting app setting details of UI if UI exists
                $ui = Get-AzResource -Name $UIName -ResourceType "Microsoft.Web/sites" -ResourceGroupName $ScanHostRGName -ErrorAction SilentlyContinue
                if($ui)
                {
                    $webapp = Get-AzWebApp -ResourceGroupName $ScanHostRGName  -Name $ui.Name -ErrorAction SilentlyContinue
                    if(($null -ne $webapp) -and (($webapp.SiteConfig.AppSettings.Name -contains "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING") -or ($webapp.SiteConfig.AppSettings.Name -contains "WEBSITE_CONTENTSHARE")) )
                    {
                        $UiDeletionwarningMsg = "[Warning]: Running installation command on an existing AzTS setup requires removing the current AzTS UI [$($UIName)] & redeploying it with updated the app settings."

                        Write-Host $UiDeletionwarningMsg -ForegroundColor $([Constants]::MessageType.warning)
                        $UiDeletionFlag = Read-Host -Prompt "`n`rAllow removal of current AzTS UI Y/N"
                        if($UiDeletionFlag -eq 'Y')
                        {
                            Write-Host "Removing current AzTS UI [$($UIName)]. This will take 1-2 min.." -ForegroundColor Yellow
                            # delete UI slot
                            $UiSlotName =  (Get-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $ui.Name).Name
                            $UiSlotName = $UiSlotName.split('/')[1]
                            $DeletedUIslot = Remove-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $ui.Name -Slot $UiSlotName -Force
                            #delete UI
                            $DeletedUi = Remove-AzWebApp -ResourceGroupName $ScanHostRGName -Name $ui.Name -Force
                            Write-Host "Removed existing AzTS UI [$($ui.Name)].`nContinuing with re-deployment of AzTS UI with updated app settings..." -ForegroundColor Yellow
                        }
                        else
                        {
                            Write-Host "Terminating Azure Tenant Security Solution setup..." -ForegroundColor Cyan
                            Write-Host $([ScannerConstants]::DoubleDashLine)
                            break;
                        }
                    }
                }

                # Stop existing app services to unlock files; If any file is locked, deployment will fail
                $AppServices = Get-AzWebApp -ResourceGroupName $ScanHostRGName 

                if($AppServices -ne $null -and $AppServices.Count-gt 0)
                {
                    $FunctionApps = $AppServices | Where-Object { $_.Kind -eq 'functionapp'}
                    $AppServices | ForEach-Object { $AppServiceSlots += Get-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $_.Name }
                }

                # Stop function apps
                if($FunctionApps -ne $null -and $FunctionApps.Count-gt 0)
                {
                    Write-Verbose "$(Get-TimeStamp)Stopping function app(s) for deployment. This is required to unblock any file in use..."
                    $FunctionApps | Stop-AzWebApp
                    Write-Verbose "$(Get-TimeStamp)Stopped function app(s): $([string]::Join(", ", ($FunctionApps | Select Name -Unique).Name))"
                    
                }

                # Start deployment slot 
                if($AppServiceSlots -ne $null -and $AppServiceSlots.Count-gt 0)
                {
                    Write-Verbose "$(Get-TimeStamp)Starting app service slot for deployment. This is required as an inactive slot cannot be updated."
                    $AppServiceSlots | Start-AzWebAppSlot
                    Write-Verbose "$(Get-TimeStamp)Started app service slot(s): $([string]::Join(", ", ($AppServiceSlots | Select Name -Unique).Name))"
                    
                }

                Write-Verbose "$(Get-TimeStamp)Checking resource deployment template..." #-ForegroundColor $([Constants]::MessageType.Info)
                
                $validationResult = Test-AzResourceGroupDeployment -Mode Incremental -ResourceGroupName $ScanHostRGName -TemplateFile $TemplateFilePath -TemplateParameterObject $TemplateParameters 
                if($validationResult)
                {
                    Write-Host "`n`rTemplate deployment validation returned following errors:" -ForegroundColor $([Constants]::MessageType.Error)
                    $validationResult | FL Code, Message | Out-String | Out-Host;
                    return;
                }
                else
                {
                    # Deploy template
                    $deploymentName = "AzTSenvironmentsetup-$([datetime]::Now.ToString("yyyymmddThhmmss"))"
                    $deploymentResult = New-AzResourceGroupDeployment -Name $deploymentName -Mode Incremental -ResourceGroupName $ScanHostRGName -TemplateFile $TemplateFilePath -TemplateParameterObject $TemplateParameters  -ErrorAction Stop -verbose 
                    Write-Verbose "$(Get-TimeStamp)Completed resources deployment for azure tenant security solution."
                
                    #Update App registered in AAD
                    #Web App

                    # update the re-direct uri of azts ui app if WAF is enabled
                    if($EnableWAF -and  $deploymentResult.Outputs.ContainsKey('azTSUIFrontDoorUrl') -and $deploymentResult.Outputs.ContainsKey('uiAppName') )
                    {
                        $AzTSUIFrontDoorUrl = $deploymentResult.Outputs.azTSUIFrontDoorUrl.Value
                        $UIAzureADAppName = $deploymentResult.Outputs.uiAppName.Value
                        $replyUris = New-Object Collections.Generic.List[string]
                        $replyUris.Add(($AzTSUIFrontDoorUrl));
                        $replyUris.Add($([string]::Join("/", $([string]::Format($AzTSUIFrontDoorUrl)), "auth.html")));
                        $replyUris.Add(($AzureEnvironmentAppServiceURI.$AzureEnvironmentName -f $UIAzureADAppName));
                        $replyUris.Add($([string]::Join("/", $([string]::Format($AzureEnvironmentAppServiceURI.$AzureEnvironmentName, $UIAzureADAppName)), "auth.html")));

                        $webUIApp = Get-AzureADApplication -Filter "AppId eq '$UIAzureADAppId'"

                        Set-AzureADApplication -ObjectId $webUIApp.ObjectId -ReplyUrls $replyUris
                    }

                    if($EnableAzTSUI -and $deploymentResult.Outputs.ContainsKey('uiAppName') -and $deploymentResult.Outputs.ContainsKey('webApiName'))
                    {
                        $azureUIAppName= $DeploymentResult.Outputs.uiAppName.Value
                        $azureWebApiName= $DeploymentResult.Outputs.webApiName.Value
                        $UIUrl =  $([string]::Concat($([string]::Format($AzureEnvironmentAppServiceURI.$AzureEnvironmentName, $azureUIAppName)), "/"))
                        
                        # assigning value of azts api uri based on whether WAF is anabled or not.
                        if($EnableWAF -and  $deploymentResult.Outputs.ContainsKey('azTSAPIFrontDoorUrl'))
                        {
                            $AzTSAPIFrontDoorUrl = $deploymentResult.Outputs.azTSAPIFrontDoorUrl.Value
                            $apiUri = $AzTSAPIFrontDoorUrl
                        }
                        else
                        {
                            $apiUri = $([string]::Format($AzureEnvironmentAppServiceURI.$AzureEnvironmentName, $azureWebApiName))
                        }

                        # Load all other scripts that are required by this script.
                        . "$PSScriptRoot\ConfigureWebUI.ps1"
       
                        Configure-WebUI -TenantId $context.Tenant.Id -ScanHostRGName $ScanHostRGName -UIAppName $azureUIAppName -ApiUrl $apiUri -UIClientId $UIAzureADAppId -WebApiClientId $WebAPIAzureADAppId -AzureEnvironmentName $AzureEnvironmentName
                    }

                    # Custom event is required to Autoupdater setup event to application insight
                    if($EnableAutoUpdater)
                    {
                        SendCustomAIEvent -DeploymentResult $deploymentResult -TelemetryIdentifier $TelemetryIdentifier
                    }
                    # Applying access restriction to UI and API, if Enable WAF is turned 'ON'. We are applying access restriction from script because front door id is required here which cannot be determined at the time of template deployment.
                    if($EnableWAF -and  $deploymentResult.Outputs.ContainsKey('apiFrontDoorName') -and  $deploymentResult.Outputs.ContainsKey('uiFrontDoorName'))
                    {
                        $UIFrontDoorName = $deploymentResult.Outputs.uiFrontDoorName.Value
                        $APIFrntDoorName = $deploymentResult.Outputs.apiFrontDoorName.Value
                        $UIFrontDoor = Get-AzFrontDoor -ResourceGroupName $ScanHostRGName -Name $UIFrontDoorName
                        $APIFrontDoor = Get-AzFrontDoor -ResourceGroupName $ScanHostRGName -Name $APIFrntDoorName

                        $UiAccessRestriction = Get-AzWebAppAccessRestrictionConfig -ResourceGroupName $ScanHostRGName -Name $azureUIAppName
                        $ApiAccessRestriction = Get-AzWebAppAccessRestrictionConfig -ResourceGroupName $ScanHostRGName -Name $azureWebApiName

                        # applying restriction on UI
                        if($UiAccessRestriction.MainSiteAccessRestrictions.RuleName -notcontains 'AllowAccessFromFrontDoor')
                        {
                            Add-AzWebAppAccessRestrictionRule -ResourceGroupName $ScanHostRGName -WebAppName $azureUIAppName -Name "AllowAccessFromFrontDoor" -Priority 100 -Action Allow -ServiceTag AzureFrontDoor.Backend -HttpHeader @{'x-azure-fdid' = $UIFrontDoor.FrontDoorId}
                        }    
                        # applying restriction on API
                        if($ApiAccessRestriction.MainSiteAccessRestrictions.RuleName -notcontains 'AllowAccessFromFrontDoor')
                        {
                            Add-AzWebAppAccessRestrictionRule -ResourceGroupName $ScanHostRGName -WebAppName $azureWebApiName -Name "AllowAccessFromFrontDoor" -Priority 100 -Action Allow -ServiceTag AzureFrontDoor.Backend -HttpHeader @{'x-azure-fdid' = $APIFrontDoor.FrontDoorId}
                        }
                    }
                    
                }                
            }
            catch
            {
                Write-Host "`rTemplate deployment returned following errors: [$($_)]." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }
            finally
            {
                # Start app services if it was stopped before deployment
                if($FunctionApps -ne $null -and $FunctionApps.Count -gt 0)
                {
                    Write-Verbose "$(Get-TimeStamp)Starting function app(s)..."
                    $FunctionApps | Start-AzWebApp
                    Write-Verbose "$(Get-TimeStamp)Started function app(s): $([string]::Join(", ", ($FunctionApps | Select Name -Unique).Name))"
                }

                # Stop deployment slot 
                if($EnableAzTSUI -and $AppServiceSlots -ne $null -and $AppServiceSlots.Count-gt 0)
                {
                    Write-Verbose "$(Get-TimeStamp)Stopping app service slot after updating the slot. This is required as an inactive slot cannot be updated."
                    $AppServiceSlots | Stop-AzWebAppSlot
                    Write-Verbose "$(Get-TimeStamp)Stopped app service slot(s): $([string]::Join(", ", ($AppServiceSlots | Select Name -Unique).Name))"
                    
                }
            }
            # Post deployment steps
            Write-Verbose "$(Get-TimeStamp)Starting post deployment environment steps.." 
            try
            {
                # Check if queue exist; else create new queue
                $storageAccountName = [string]::Empty;
                $storageQueueName = [string]::Empty;
                Write-Verbose "$(Get-TimeStamp)Creating Storage queue to queue the subscriptions for scan.." #-ForegroundColor $([Constants]::MessageType.Info)
                if( $deploymentResult.Outputs.ContainsKey('storageId') -and $deploymentResult.Outputs.ContainsKey('storageQueueName'))
                {
                    $storageAccountName = $deploymentResult.Outputs.storageId.Value.Split("/")[-1]
                    $storageQueueName = $deploymentResult.Outputs.storageQueueName.Value

                    # Create a queue in central storage account
                    try
                    {
                        Write-Verbose "$(Get-TimeStamp)Creating Storage queue in central storage account. This queue will be used to request subscription scan."
                        if($EnableCentralVisibility -eq $true -and ![string]::IsNullOrWhiteSpace($CentralStorageAccountConnectionString))
                        {
                            $storageContext = New-AzStorageContext -ConnectionString $CentralStorageAccountConnectionString -ErrorAction Stop
                            $storageQueue = Get-AzStorageQueue -Name $storageQueueName -Context $storageContext -ErrorAction SilentlyContinue
                            if(-not $storageQueue)
                            {   
                                $storageQueue = New-AzStorageQueue -Name $storageQueueName -Context $storageContext -ErrorAction Stop
                            }
                        }
                    }
                    catch
                    {
                        if(($_.Exception | GM ErrorContent -ErrorAction SilentlyContinue) -and ($_.Exception.ErrorContent | GM Message -ErrorAction SilentlyContinue))
                        {
                            Write-Host "ErrorCode [$($_.Exception.ErrorCode)] ErrorMessage [$($_.Exception.ErrorContent.Message.Value)]"  -ForegroundColor $([Constants]::MessageType.Error)
                        }
                        else
                        {
                            Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
                        }
                        Write-Host "Failed to create storage queue [$($storageQueueName)] in central storage account. You can create this queue directly from portal with the name [$($storageQueueName)]. For steps to create a queue, please refer https://docs.microsoft.com/en-us/azure/storage/queues/storage-quickstart-queues-portal#create-a-queue.`n`nPlease note that central storage repository feature is currently not supported if your central storage account has network restrictions. In this case, you will have to switch to the standalone mode by running this installation command again without '-EnableCentralVisibility' parameter." -ForegroundColor $([Constants]::MessageType.Error)
                    }
                    

                    #fetching storage network settings
                    if ($EnableVnetIntegration)
                    {
                        $StorageNetworkSetting = (Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $ScanHostRGName -AccountName $storageAccountName).DefaultAction

                        if ($StorageNetworkSetting -eq 'Deny')
                        {
                            # Changing storage network setting to allow "All networks", in order to fetch queue details
                            # This is required as storage with network restriction will not be accessible from user's machine and in such case fetching queue details will result into error 
                            Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $ScanHostRGName -Name $storageAccountName -Bypass AzureServices -DefaultAction Allow
                            # wait for 30 sec for the settings to get updated on storage account
                            Start-Sleep -Seconds 30
                        }
                    }

                    $storageAccountKey = Get-AzStorageAccountKey -ResourceGroupName $ScanHostRGName -Name $storageAccountName -ErrorAction Stop
                    if(-not $storageAccountKey)
                    {
                        throw [System.ArgumentException] ("Unable to fetch 'storageAccountKey'. Please check if you have the access to read storage key.");
                    }
                    else
                    {
                        $storageAccountKey = $storageAccountKey.Value[0]
                    }

                    $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName  -StorageAccountKey $storageAccountKey -ErrorAction Stop
                    $storageQueue = Get-AzStorageQueue -Name $storageQueueName -Context $storageContext -ErrorAction SilentlyContinue
                    if(-not $storageQueue)
                    {   
                        $storageQueue = New-AzStorageQueue -Name $storageQueueName -Context $storageContext -ErrorAction Stop
                    }

                    if($EnableVnetIntegration)
                    {
                        # Setting storage network settings back to "restricted networks"
                        Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $ScanHostRGName -Name $storageAccountName -Bypass AzureServices -DefaultAction Deny
                    }
                }
                else
                {
                    Write-Host "Failed to create Storage queue." -ForegroundColor $([Constants]::MessageType.Error)
                    return
                }

                # Adding virtual network rules to storage, to configure service endpoints
                # Virtual network rules are not added from template, as all function apps have dependency on storage, so storage gets created first and network rules are applied to it. But once network is restricted, function app cannot communicate with storage to get values like - connection string as they are still not a part of vnet and hence the deployment fails. 
                if($EnableVnetIntegration)
                {
                    $subnetId = @();
                    $subnetTobeAdded = @();

                    if($deploymentResult.Outputs.ContainsKey('vnet'))
                    {
                        $vnetName = $deploymentResult.Outputs.vnet.Value

                        #configuring virtual ntwork rules
                        $subnetId += Get-AzVirtualNetwork -ResourceGroupName $ScanHostRGName -Name $vnetName | Get-AzVirtualNetworkSubnetConfig
                        $subnetTobeAdded += $subnetId | Where-Object { $_.Name -notmatch "PrivateEndpointSubnet"}
                        $subnetTobeAdded | ForEach-Object { 
                            Add-AzStorageAccountNetworkRule -ResourceGroupName $ScanHostRGName -Name $storageAccountName -VirtualNetworkResourceId $_.Id 
                        } 
                        
                    }
                }
        

                # Set monitoring alert
                Set-AzTSMonitoringAlert -DeploymentResult $deploymentResult `
                                        -SendAlertNotificationToEmailIds $SendAlertNotificationToEmailIds `
                                        -Location $Location `
                                        -ScanHostRGName $ScanHostRGName `
                                        -TelemetryIdentifier $TelemetryIdentifier `
                                        -IsAutoUpdaterEnabled $EnableAutoUpdater

                Write-Host "`rCompleted installation for Azure Tenant Security Solution." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "$([Constants]::DoubleDashLine)" #-ForegroundColor $([Constants]::MessageType.Info)
                if($EnableAzTSUI -and $EnableWAF)
                {
                    Write-Host "$([Constants]::NextSteps -f $AzTSUIFrontDoorUrl)" -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host "IMPORTANT: AzTS UI will be available only after completing 'step a' listed under Next steps. AzTS UI URL for your tenant: $($AzTSUIFrontDoorUrl)" -ForegroundColor $([Constants]::MessageType.Warning)
                }
                elseif($EnableAzTSUI)
                {
                    Write-Host "$([Constants]::NextSteps -f $UIUrl)" -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host "IMPORTANT: AzTS UI will be available only after completing 'step a' listed under Next steps. AzTS UI URL for your tenant: $($UIUrl)" -ForegroundColor $([Constants]::MessageType.Warning)
                }
                else 
                {
                    Write-Host "$([Constants]::NextSteps -f $UIUrl)" -ForegroundColor $([Constants]::MessageType.Info)
                }
                Write-Host "$([Constants]::DoubleDashLine)"
            }
            catch
            {
                Write-Host "Error occurred while executing post deployment steps. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            }

            return $deploymentResult
        }
}

class Constants
{
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
	    Default = [System.ConsoleColor]::White
    }

    static [string] $InstallSolutionInstructionMsg = "This command will perform 5 important operations. It will:`r`n`n" + 
					"   [1] Create resources needed to support Azure Tenant Security scan `r`n" +
                    "   [2] Deploy AzTS packages to azure function app `r`n" +
					"   [3] Deploy UI and API packages to respective azure web service apps `r`n" +
                    "   [4] Schedule daily subscription scan `r`n" +
                    "   [5] Setup monitoring alerts `r`n`n" +
                    "More details about resources created can be found in the link: http://aka.ms/DevOpsKit/TenantSecuritySetup `r`n"
    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
    
    static [string] $NextSteps = "** Next steps **`r`n" + 
    "        a) Azure Tenant security scan will start on scheduled time (UTC 01:00).`r`n" +
    "              ** OR  **`r`n"+
    "           You can trigger scan using 'Start-AzSKTenantSecuritySolutionOnDemandScan -SubscriptionId <HostSubscriptionId> -ScanHostRGName <HostResourceGroupName>' command.`r`n"+
    "        b) After scan completion, all security control results will be sent to LA workspace and Storage account present in your hosting subscription scan RG.`r`n" +
    "        c) Using the AzTS UI ({0}) you can monitor all the compliance detail of the controls for all the subscriptions which were scanned through 'step a'. or you can trigger new adhoc scan for subscriptions of your choice through UI itself and monitor new compliance details.`r`n"+
    "        d) You can create compliance monitoring Power BI dashboard using link: http://aka.ms/DevOpsKit/TenantSecurityDashboard.`r`n" +
    "`r`nFor any feedback contact us at: azsksup@microsoft.com.`r`n"

    static [string] $AzureADAppSetupInstructionMsg = "This command will perform 5 important operations. It will:`r`n`n" +
                    "   [1] Create Azure AD application for UI, if it does not exist. `r`n" +
                    "   [2] Create Azure AD application for API, if it does not exist. `r`n" +
                    "   [3] Update UI AD application redirection URL. `r`n" +
                    "   [4] Grant AD applications permission to request OAuth2.0 implicit flow access tokens. This is required for browser-based apps. `r`n" +
                    "   [5] Grant 'User.Read' permission to UI AD application. This permission is used to read logged in user's details such as name, email, and photo.";
    
    static [string] $AzureADAppSetupNextSteps = "** Next steps **`r`n" + 
                    "Use Install-AzSKTenantSecuritySolution command to complete the setup. `r`n" +
                    "The AD application (client) ids listed below needs to be passed as input parameters to the installation command: `r`n" +
                    "   [1] WebAPIAzureADAppId: {0} `r`n" +
                    "   [2] UIAzureADAppId: {1} `r`n";

    static [string] $ScanningIdentitySetupInstructionMsg = "This command will perform 2 important operations. It will:`r`n`n" +
                    "   [1] Create user-assigned managed identity which will be used for centrally scanning your subscriptions. `r`n" +
                    "   [2] Assign 'Reader' access to user-assigned managed identity on target subscription(s) that needs to be scanned. `r`n";
    
    static [string] $ScanningIdentitySetupNextSteps = "** Next steps **`r`n" + 
                    "Use Grant-AzSKGraphPermissionToUserAssignedIdentity command to grant graph permission to this scanner identity. This permission will be required to read data in your organization's directory such as Privileged Identity Management (PIM), users, groups and apps details.`r`n";

    static [string] $AutoUpdaterFailureAlertQuery = "customEvents
                                                | where name == 'AzTS_Service_AutoUpdateOverallProgressTracker'
                                                | where customDimensions.Id == '{0}'
                                                | where timestamp > ago(3d)
                                                | extend isOverallSuccess = tostring(customDimensions.isOverallSuccess)
                                                | extend EventType = tostring(customDimensions.EventType)
                                                | where EventType =~ 'Completed'
                                                | summarize arg_max(timestamp, *)
                                                | project EventType, isOverallSuccess
                                                | where isOverallSuccess == true";


    static [string] $NewReleaseAlertQuery = "// Get currently installed version for an app service.
                                        customEvents
                                        | where name == 'AzTS_Service_AutoUpdateVersionTracker'
                                        | where customDimensions.Id == '{0}'
                                        | where timestamp > ago(2d)
                                        | extend FeatureName = tolower(tostring(customDimensions.FeatureName))
                                        | extend AppName = tolower(tostring(customDimensions.AppName))
                                        | extend Status= tostring(customDimensions.Status), CurrentVersion= tostring(customDimensions.CurrentVersion)
                                        | where FeatureName != dynamic(null) and AppName != dynamic(null)
                                        | where Status =~ 'Succeeded' or Status =~ 'AlreadyUpToDate'
                                        | summarize arg_max(timestamp, LatestRecord = CurrentVersion), arg_min(timestamp, PrevRecord = CurrentVersion) by FeatureName, AppName
                                        | where LatestRecord != PrevRecord
                                        | project FeatureName, AppName, UpgradedFrom = PrevRecord , UpgradedTo = LatestRecord"

    static [string] $SubscriptionInvRefreshFailureQuery = "let TablePlaceholder = view () {print SubscriptionId = 'SubscriptionIdNotFound'};
                                                      let SubInventory_CL = union isfuzzy=true TablePlaceholder, (union (
                                                      AzSK_SubInventory_CL | where TimeGenerated > ago(24h)
                                                      | distinct SubscriptionId
                                                      ))
                                                      | where SubscriptionId !~ 'SubscriptionIdNotFound';
                                                      SubInventory_CL";
    static [string] $BaselineControlsInvRefreshFailureQuery = "let TablePlaceholder = view () {print ControlId_s = 'NA'};
                                                          let BaselineControlsInv_CL = union isfuzzy=true TablePlaceholder, (union (
                                                          AzSK_BaselineControlsInv_CL | where TimeGenerated > ago(24h)
                                                          | distinct ControlId_s
                                                          ))
                                                          | where ControlId_s !~ 'NA';
                                                          BaselineControlsInv_CL";
    static [string] $RBACInvRefreshFailureQuery = "let TablePlaceholder = view () {print NameId = 'NA', RoleId = 'NA'};
                                              let RBAC_CL = union isfuzzy=true TablePlaceholder, (union (
                                              AzSK_RBAC_CL | where TimeGenerated > ago(24h)
                                              | take 10
                                              ))
                                              | where NameId !~ 'NA';
                                              RBAC_CL";
    static [string] $ControlResultsRefreshFailureQuery = "let TablePlaceholder = view () {print SubscriptionId = 'SubscriptionIdNotFound'};
                                                     let ControlResults_CL = union isfuzzy=true TablePlaceholder, (union (
                                                     AzSK_ControlResults_CL | where TimeGenerated > ago(24h)
                                                     | distinct SubscriptionId
                                                     ))
                                                     | where SubscriptionId !~ 'SubscriptionIdNotFound';
                                                     ControlResults_CL
                                                     | take 10";

    static [string] $ScanProgressSummaryQuery = "let TablePlaceholder = view () { print SubscriptionId = 'SubscriptionIdNotFound' };
                                            let ProcessedSubscriptions_CL = union isfuzzy=true TablePlaceholder, (union (
                                                        AzSK_ProcessedSubscriptions_CL
                                                        | where TimeGenerated > ago(2d)
                                                        | where JobId_d == toint(format_datetime(now(), 'yyyyMMdd'))
                                                        | where EventType_s == 'Completed' and OverallProcessCompleted_b == true
                                                        | distinct SubscriptionId
                                                        ))
                                                | where SubscriptionId <> 'SubscriptionIdNotFound';
                                            let SubInventory_CL = union isfuzzy=true TablePlaceholder, (union (
                                                        AzSK_SubInventory_CL
                                                        | where TimeGenerated > ago(2d)
                                                        | where JobId_d == toint(format_datetime(now(), 'yyyyMMdd'))
                                                        | where State_s != 'Disabled'
                                                        | distinct SubscriptionId
                                                        ))
                                                | where SubscriptionId <> 'SubscriptionIdNotFound';
                                            SubInventory_CL
                                            | project SubscriptionId
                                            | join kind= leftouter
                                            (
                                            ProcessedSubscriptions_CL
                                            )
                                            on SubscriptionId
                                            | extend Type = iff(SubscriptionId1 != dynamic(null), 'Completed', 'NotCompleted')
                                            | summarize count() by Type";

}

function Set-AzTSMonitoringAlert
{
    param (
        [PSObject] $DeploymentResult,
        [string[]] $SendAlertNotificationToEmailIds,
        [string] $Location,
        [string] $ScanHostRGName,
        [string] $TelemetryIdentifier,
        [bool] $IsAutoUpdaterEnabled
    )

    try
    {        
        Write-Verbose "$(Get-TimeStamp)Creating monitoring alerts..."
                
        $EmailReceivers = @()
        $SendAlertNotificationToEmailIds | ForEach-Object {
            $EmailReceivers += New-AzActionGroupReceiver -Name "Notify_$($_)" -EmailReceiver -EmailAddress $_
        }

        $alertActionGroup = Set-AzActionGroup -Name ‘AzTSAlertActionGroup’ -ResourceGroupName $ScanHostRGName -ShortName ‘AzTSAlert’ -Receiver $EmailReceivers -WarningAction SilentlyContinue


        if($DeploymentResult.Outputs.ContainsKey('logAnalyticsResourceId') -and $DeploymentResult.Outputs.ContainsKey('applicationInsightsId'))
        {
            $LADataSourceId = $DeploymentResult.Outputs.logAnalyticsResourceId.Value
            $AIDataSourceId = $DeploymentResult.Outputs.applicationInsightsId.Value
            
            $deploymentName = "AzTSenvironmentmonitoringsetup-$([datetime]::Now.ToString("yyyymmddThhmmss"))"

            New-AzResourceGroupDeployment -Name  $deploymentName `
                                          -Mode Incremental `
                                          -ResourceGroupName $ScanHostRGName  `
                                          -TemplateFile ".\MonitoringAlertTemplate.json" `
                                          -AutoUpdaterFailureAlertQuery ([string]::Format([Constants]::AutoUpdaterFailureAlertQuery, $TelemetryIdentifier)) `
                                          -AutoUpdaterNewReleaseAlertQuery ([string]::Format([Constants]::NewReleaseAlertQuery, $TelemetryIdentifier)) `
                                          -SubscriptionInvRefreshFailureAlertQuery ([Constants]::SubscriptionInvRefreshFailureQuery) `
                                          -BaselineControlsInvRefreshFailureAlertQuery ([Constants]::BaselineControlsInvRefreshFailureQuery) `
                                          -RBACInvRefreshFailureAlertQuery ([Constants]::RBACInvRefreshFailureQuery) `
                                          -ControlResultsRefreshFailureAlertQuery ([Constants]::ControlResultsRefreshFailureQuery) `
                                          -ScanProgressSummaryQuery ([Constants]::ScanProgressSummaryQuery) `
                                          -ActionGroupId $alertActionGroup.Id `
                                          -AIResourceId $AIDataSourceId `
                                          -LAResourceId $LADataSourceId `
                                          -IsAutoUpdaterEnabled $IsAutoUpdaterEnabled

             Write-Verbose "$(Get-TimeStamp)Completed monitoring alert setup."

        }
        else
        {
            Write-Host "Failed to setup monitoring alert. Either Application Insight ID or Log Analytics ID is either null or empty." -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }
    catch
    {
        if(($_.Exception | GM ErrorContent -ErrorAction SilentlyContinue) -and ($_.Exception.ErrorContent | GM Message -ErrorAction SilentlyContinue))
        {
            Write-Host "ErrorCode [$($_.Exception.ErrorCode)] ErrorMessage [$($_.Exception.ErrorContent.Message.Value)]"  -ForegroundColor $([Constants]::MessageType.Error)
        }
        else
        {
            Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
        }
    }
}

# Execute this function to send initial setup event to application insight. This is required as the auto-updater can take up to 24 hours to start after the initial setup.
# In the meantime, this custom events suppresses the Auto-Updater failure alert.
function SendCustomAIEvent
{
    param (
        [PSObject] $DeploymentResult,
        [string] $TelemetryIdentifier
    )
    try
    {
        if( $DeploymentResult.Outputs.ContainsKey('applicationInsightsIKey'))
        {
            $InstrumentationKey = $DeploymentResult.Outputs.applicationInsightsIKey.Value
            $azAccountsModuleInfo = Get-Module Az.Accounts -ListAvailable -Verbose:$false | Select-Object -First 1
            if($null -eq $azAccountsModuleInfo)
            {
                Install-Module -Name Az.Accounts -Scope CurrentUser -Repository 'PSGallery' -AllowClobber -Verbose:$false
                $azAccountsModuleInfo = Get-Module Az.Accounts -ListAvailable -Verbose:$false | Select-Object -First 1
            }
            $AssemblyPath = Get-ChildItem -Path $azAccountsModuleInfo.ModuleBase -Filter "Microsoft.ApplicationInsights.dll" -Recurse
            $AssemblyPathFullName = $AssemblyPath.FullName | Sort-Object -Descending | Select-Object -First 1
            Add-Type -Path $AssemblyPathFullName
            $client = [Microsoft.ApplicationInsights.TelemetryClient]::new()
            $client.InstrumentationKey= $InstrumentationKey
            $event = [Microsoft.ApplicationInsights.DataContracts.EventTelemetry]::new()
            $event.Name = "AzTS_Service_AutoUpdateOverallProgressTracker"
            $customProperties = @{
                isOverallSuccess = $true;
                Id = $TelemetryIdentifier
                isAppServiceAutoUpdateSuccess = $true;
                isCheckForAutoUpdateSuccess = $true;
                isGetAppServicesByResourceGroupSuccess = $true;
                isReconcilationCheckSuccess = $true;
                message = "This is an initial setup event."
            }
            $customProperties.Keys | ForEach-Object {
                            try {
                                $event.Properties[$_] = $customProperties[$_].ToString();
                            }
                            catch
            				{
                                $_
            					# Eat the current exception which typically happens when the property already exist in the object and try to add the same property again
            					# No need to break execution
            				}
                        }
            
            $client.TrackEvent($event) 
            $client.Flush()
        }
    }
    catch
    {
        # Eat the current exception which typically happens when dll is not available
    }

}

class ContextHelper
{
    $currentContext = $null;

    [PSObject] SetContext([string] $SubscriptionId)
    {
            $this.currentContext = $null
            if(-not $SubscriptionId)
            {

                Write-Host "The argument 'SubscriptionId' is null. Please specify a valid subscription id." -ForegroundColor $([Constants]::MessageType.Error)
                return $null;
            }

            # Login to Azure and set context
            try
            {
                if(Get-Command -Name Get-AzContext -ErrorAction Stop)
                {
                    $this.currentContext = Get-AzContext -ErrorAction Stop
                    $isLoginRequired = (-not $this.currentContext) -or (-not $this.currentContext | GM Subscription) -or (-not $this.currentContext | GM Account)
                    
                    # Request login if context is empty
                    if($isLoginRequired)
                    {
                        Write-Host "No active Azure login session found. Initiating login flow..." -ForegroundColor $([Constants]::MessageType.Warning)
                        $this.currentContext = Connect-AzAccount -ErrorAction Stop # -SubscriptionId $SubscriptionId
                    }
            
                    # Switch context if the subscription in the current context does not the subscription id given by the user
                    $isContextValid = ($this.currentContext) -and ($this.currentContext | GM Subscription) -and ($this.currentContext.Subscription | GM Id)
                    if($isContextValid)
                    {
                        # Switch context
                        if($this.currentContext.Subscription.Id -ne $SubscriptionId)
                        {
                            $this.currentContext = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
                        }
                    }
                    else
                    {
                        Write-Host "Invalid PS context. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    }
                }
                else
                {
                    Write-Host "Az command not found. Please run the following command 'Install-Module Az -Scope CurrentUser -Repository 'PSGallery' -AllowClobber -SkipPublisherCheck' to install Az module." -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch
            {
                Write-Host "Error occurred while logging into Azure. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                return $null;
            }

            return $this.currentContext;
    
    }
    
}

class CentralPackageInfo
{
    [PSObject] $CentralPackageObject = $null
    [string] $CentralPackageURL = [string]::Empty
    [string] $MetadataAggregatorPackageURL = [string]::Empty
    [string] $WorkItemProcessorPackageURL = [string]::Empty
    [string] $WebApiPackageURL = [string]::Empty
    [string] $UIPackageURL = [string]::Empty

    CentralPackageInfo()
    {
        $CentralPackageVersionResponse = Invoke-WebRequest -UseBasicParsing -Uri "https://aka.ms/AzTS/CentralPackageURL" -Method Get
        if(($CentralPackageVersionResponse | Measure-Object).Count -gt 0 -and $CentralPackageVersionResponse.StatusCode -eq 200)
        {
            $this.CentralPackageObject = $CentralPackageVersionResponse.Content | ConvertFrom-Json
        
            if(($this.CentralPackageObject | Get-Member BasePackageLink -ErrorAction SilentlyContinue) -ne $null)
            {
                $this.CentralPackageURL = $this.CentralPackageObject.BasePackageLink
            }    
        }

        $this.MetadataAggregatorPackageURL = $this.GetPackageURL("MetadataAggregator")
        $this.WorkItemProcessorPackageURL = $this.GetPackageURL("WorkItemProcessor")
        $this.WebApiPackageURL = $this.GetPackageURL("WebApi")
        $this.UIPackageURL = $this.GetPackageURL("UI")
    }

    [string] GetPackageVersion([string] $featureName)
    {
        $packageVersion = "1.0.0"
        if(($this.CentralPackageObject | Get-Member Packages -ErrorAction SilentlyContinue) -ne $null)
        {
            $packageDetails = $this.CentralPackageObject.Packages | Where-Object { $_.Name -eq $featureName }
        
            if(($packageDetails | Get-Member Stable -ErrorAction SilentlyContinue) -ne $null)
            {
                $packageVersion = $packageDetails.Stable
            }
        }

        return $packageVersion
    }

    [string] GetPackageName([string] $featureName)
    {
        $packageName = $featureName + ".zip";
        if(($this.CentralPackageObject | Get-Member Packages -ErrorAction SilentlyContinue) -ne $null)
        {
            $packageDetails = $this.CentralPackageObject.Packages | Where-Object { $_.Name -eq $featureName }
        
            if(($packageDetails | Get-Member PackageName -ErrorAction SilentlyContinue) -ne $null)
            {
                $packageName = $packageDetails.PackageName
            }
        }

        return $packageName
    }

    [string] GetPackageURL([string] $featureName)
    {
        return [string]::Join("/",$this.CentralPackageURL, 
                                  $featureName,
                                  $this.GetPackageVersion($featureName),
                                  $this.GetPackageName($featureName))
    }

}

function Get-TimeStamp {
    return "{0:h:m:ss tt} - " -f (Get-Date -UFormat %T)
}

Function CreateAzureADApplication
{
    param (
        [string] $displayName
    )

    Write-Host "Checking if Azure AD application [$($displayName)] already exist..." -ForegroundColor $([Constants]::MessageType.Info)

    if (!(Get-AzureADApplication -SearchString $displayName)) {

        Write-Host "Creating new AD application [$($displayName)]..." -ForegroundColor $([Constants]::MessageType.Info)
        # create new application
        $app = New-AzureADApplication -DisplayName $displayName

        # create a service principal for your application
        $spForApp = New-AzureADServicePrincipal -AppId $app.AppId 
    }
    else
    {
        Write-Host "AD application [$($displayName)] already exists." -ForegroundColor $([Constants]::MessageType.Info)
        $app = Get-AzureADApplication -SearchString $displayName
    }
    #endregion
    return $app
}

function GetADPermissionToBeGranted
{
    param
    (
        [string] $targetServicePrincipalAppId,
        $appPermissionsRequired
    )

    $targetSp = Get-AzureADServicePrincipal -Filter "AppId eq '$($targetServicePrincipalAppId)'"

    $RoleAssignments = @()
    Foreach ($AppPermission in $appPermissionsRequired) {
        $RoleAssignment = $targetSp.Oauth2Permissions | Where-Object { $_.Value -eq $AppPermission}
        $RoleAssignments += $RoleAssignment
    }

    $ResourceAccessObjects = New-Object 'System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]'
    foreach ($RoleAssignment in $RoleAssignments) {
        $resourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess"
        $resourceAccess.Id = $RoleAssignment.Id
        $resourceAccess.Type = 'Scope'
        $ResourceAccessObjects.Add($resourceAccess)
    }
    $requiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $requiredResourceAccess.ResourceAppId = $targetSp.AppId
    $requiredResourceAccess.ResourceAccess = $ResourceAccessObjects

    return $requiredResourceAccess
    
}

function get-hash([string]$textToHash) {
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
    $hashByteArray = $hasher.ComputeHash($toHash)
    $result = [string]::Empty;
    foreach($byte in $hashByteArray)
    {
      $result += "{0:X2}" -f $byte
    }
    return $result;
 }


function Grant-AzSKGraphPermissionToUserAssignedIdentity
{
    Param
    (
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which Azure Tenant Security Solution needs to be installed.")]
        $SubscriptionId,

        [string]
		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Name of ResourceGroup where user identity has been created.")]
		$ResourceGroupName,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Object id of user managed identity used to scan subscriptions.")]
        $IdentityName,

        [string[]]
        [Parameter(Mandatory = $true, HelpMessage="List of Microsoft Graph permission to be granted to the Managed Identity")]
        $MSGraphPermissionsRequired,

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage="List of Azure AD Graph permission to be granted to the Managed Identity")]
        $ADGraphPermissionsRequired,

        [string]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ParameterSetName = "UserIdentity", HelpMessage="Object id of user managed identity used to scan subscriptions.")]
        $UserAssignedIdentityObjectId
    )

    try {

        Write-Host "WARNING: To grant Graph API permission, the signed-in user must be a member of one of the following administrator roles: Global Administrator or Privileged Role Administrator." -ForegroundColor $([Constants]::MessageType.Warning)
        
        
        # Validate input
        if([string]::IsNullOrWhiteSpace($UserAssignedIdentityObjectId)) 
        {
            Write-Host "Getting Azure AD enterprise application details..." -ForegroundColor $([Constants]::MessageType.Info)
            $UserAssignedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName
            $UserAssignedIdentityObjectId = $UserAssignedIdentity.PrincipalId
        }
        $msi = Get-AzureADServicePrincipal -ObjectId $UserAssignedIdentityObjectId
        $groupPermissions = @()
        
        if(($MSGraphPermissionsRequired | Measure-Object).Count -gt 0)
        {
            # MS Graph ID
            $targetServicePrincipalAppId='00000003-0000-0000-c000-000000000000'
            $graph = Get-AzureADServicePrincipal -Filter "AppId eq '$($targetServicePrincipalAppId)'"
            $groupPermissions += @($graph.AppRoles | Where { $MSGraphPermissionsRequired -contains $_.Value -and $_.AllowedMemberTypes -contains "Application"} `
                                                   | Select *, @{ Label = "PermissionScope"; Expression = {"MS Graph"}}, `
                                                               @{ Label = "GraphServicePrincipalObjectId"; Expression = {$graph.ObjectId}})
        }

        if(($ADGraphPermissionsRequired | Measure-Object).Count -gt 0)
        {
            # Azure AD Graph ID
            $targetServicePrincipalAppId='00000002-0000-0000-c000-000000000000'
            $graph = Get-AzureADServicePrincipal -Filter "AppId eq '$($targetServicePrincipalAppId)'"
            $groupPermissions += @($graph.AppRoles | Where { $ADGraphPermissionsRequired -contains $_.Value -and $_.AllowedMemberTypes -contains "Application"}  `
                                                   | Select *, @{ Label = "PermissionScope"; Expression = {"Azure AD Graph"}}, `
                                                               @{ Label = "GraphServicePrincipalObjectId"; Expression = {$graph.ObjectId}})
        }
        
        # Grant permission to managed identity.
        if(($groupPermissions | Measure-Object).Count -gt 0)
        {
            $groupPermissions | ForEach-Object {

                Write-Host "Granting $($_.PermissionScope) [$($_.Value)] permission to Azure AD enterprise application [ObjectId: $($UserAssignedIdentityObjectId)]." -ForegroundColor $([Constants]::MessageType.Info)

                try 
                {
                    $RoleAssignment = New-AzureADServiceAppRoleAssignment `
                                                                -Id $_.Id `
                                                                -ObjectId $msi.ObjectId `
                                                                -PrincipalId $msi.ObjectId `
                                                                -ResourceId $_.GraphServicePrincipalObjectId
                    Write-Host "Successfully granted [$($_.Value)] permission to Azure AD enterprise application." -ForegroundColor $([Constants]::MessageType.Update)
                }
                catch
                {
                    if(($_.Exception | GM ErrorContent -ErrorAction SilentlyContinue) -and ($_.Exception.ErrorContent | GM Message -ErrorAction SilentlyContinue))
                    {
                        Write-Host "ErrorCode [$($_.Exception.ErrorCode)] ErrorMessage [$($_.Exception.ErrorContent.Message.Value)]"  -ForegroundColor $([Constants]::MessageType.Error)
                    }
                    else
                    {
                        Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
                    }
                }
            }
        }
        else
        {
            Write-Host "WARNING: No match found for permissions provided as input." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }
    catch
    {
        if(($_.Exception | GM ErrorContent -ErrorAction SilentlyContinue) -and ($_.Exception.ErrorContent | GM Message -ErrorAction SilentlyContinue))
        {
            Write-Host "ErrorCode [$($_.Exception.ErrorCode)] ErrorMessage [$($_.Exception.ErrorContent.Message.Value)]"  -ForegroundColor $([Constants]::MessageType.Error)
        }
        else
        {
            Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
        }
    }
}


function Set-AzSKTenantSecurityADApplication
{

    Param(
        
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which Azure Tenant Security Solution needs to be installed.")]
        $SubscriptionId,

        [string]
		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Name of ResourceGroup where setup resources will be created.")]
		$ScanHostRGName = "AzSK-AzTS-RG",

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Custom", HelpMessage="Name of the Azure AD application to be used by the API.")]
        $WebAPIAzureADAppName,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Custom", HelpMessage="Name of the Azure AD application to be used by the UI.")]
        $UIAzureADAppName,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [ValidateSet("AzureCloud", "AzureGovernmentCloud")]
        $AzureEnvironmentName = "AzureCloud"

        )

        try
        {
            $output = "" | Select WebAPIAzureADAppId,UIAzureADAppId 

            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "$([Constants]::AzureADAppSetupInstructionMsg)" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "NOTE: If you do not have the permission to perform aforementioned operations, please contact your administrator to complete the setup." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)

            $ResourceId='/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId,$ScanHostRGName;
            $ResourceIdHash = get-hash($ResourceId)
            $ResourceHash = $ResourceIdHash.Substring(0,5).ToString().ToLower() #considering only first 5 characters

            Write-Host "Starting Azure AD application setup..." -ForegroundColor $([Constants]::MessageType.Info)

            # Creating Azure AD application: Web API
            if([string]::IsNullOrWhiteSpace($WebAPIAzureADAppName))
            {
                $WebAPIAzureADAppName = "AzSK-AzTS-WebApi-$ResourceHash";
            }

            $webApi = CreateAzureADApplication -displayName $WebAPIAzureADAppName

            # Creating Azure AD application: UI
            if([string]::IsNullOrWhiteSpace($UIAzureADAppName))
            {
                $UIAzureADAppName="AzSK-AzTS-UI-$ResourceHash"
            }

            $webUIApp = CreateAzureADApplication -displayName $UIAzureADAppName

            Write-Host "Updating Azure AD application registration..." -ForegroundColor $([Constants]::MessageType.Info)

            $identifierUri = 'api://{0}' -f $webUIApp.AppId
            $replyUris = New-Object Collections.Generic.List[string]
            $replyUris.Add(($AzureEnvironmentAppServiceURI.$AzureEnvironmentName -f $UIAzureADAppName));
            $replyUris.Add($([string]::Join("/", $([string]::Format($AzureEnvironmentAppServiceURI.$AzureEnvironmentName, $UIAzureADAppName)), "auth.html")));
            Set-AzureADApplication -ObjectId $webUIApp.ObjectId -ReplyUrls $replyUris -IdentifierUris $identifierUri -Oauth2AllowImplicitFlow $true
            
            $identifierUri = 'api://{0}' -f $webApi.AppId
            Set-AzureADApplication -ObjectId $webApi.ObjectId -IdentifierUris $identifierUri -Oauth2AllowImplicitFlow $true

            Write-Host "Updated Azure AD applications redirection URL and OAuth 2.0 implicit grant flow." -ForegroundColor $([Constants]::MessageType.Info)

            try
            {
                Write-Host "Granting 'User.Read' permission to UI AD application..." -ForegroundColor $([Constants]::MessageType.Info)

                # MS Graph ID
                $targetServicePrincipalAppId='00000003-0000-0000-c000-000000000000';        
                # Grant MS Graph permission
                # Get Azure AD App for UI. Grant graph permission.
                $appPermissionsRequired = @('User.Read')
                $permission = GetADPermissionToBeGranted -targetServicePrincipalAppId $targetServicePrincipalAppId -appPermissionsRequired $appPermissionsRequired
                Set-AzureADApplication -ObjectId $webUIApp.ObjectId -RequiredResourceAccess $permission
                Write-Host "Granted UI AD application 'User.Read' permission." -ForegroundColor $([Constants]::MessageType.Info)
            }
            catch
            {
                Write-Host "Failed to grant 'User.Read' permission. ExceptionMessage $($_)" -ForegroundColor Red
            }

            Write-Host "Completed Azure AD application setup." -ForegroundColor $([Constants]::MessageType.Info)

            Write-Host $([Constants]::SingleDashLine)    
            $NextStepMessage =  $([Constants]::AzureADAppSetupNextSteps) -f $webApi.AppId, $webUIApp.AppId
            $output.WebAPIAzureADAppId = $webApi.AppId
            $output.UIAzureADAppId = $webUIApp.AppId
            Write-Host "$($NextStepMessage)" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::DoubleDashLine)

            return $output;
            
        }
        catch
        {
            Write-Host "Error occurred while setting up Azure AD application. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
}


function Set-AzSKTenantSecuritySolutionScannerIdentity
{
    Param(
        
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription id in which scanner identity is to be created.")]
        $SubscriptionId,

        [string]
	    [Parameter(Mandatory = $false, HelpMessage="Name of ResourceGroup where scanner identity will be created.")]
	    $ResourceGroupName = "AzSK-AzTS-RG",

        [string]
        [Parameter(Mandatory = $true, HelpMessage="Location where scanner identity will get created. Default location is EastUS2.")]
        $Location = 'EastUS2',

        [string]
        [Parameter(Mandatory = $false, HelpMessage="Name of the Azure AD application to be used by the API.")]
        $UserAssignedIdentityName,

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage="List of target subscription(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target subscription.")]
        $TargetSubscriptionIds = @()

    )

    Begin
    {
         # Step 1: Set context to subscription where user-assigned managed identity needs to be created.
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if(-not $currentContext)
        {
            return;
        }
    }

    Process
    {
        try
        {
            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Running Azure Tenant Security scanner identity setup...`n" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::ScanningIdentitySetupInstructionMsg ) -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Step 2: Create resource group where user-assigned MI resource will be created. 
            try
            {
               Write-Verbose "$(Get-TimeStamp)Checking resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
                if(-not $rg)
                {
                    Write-Verbose "$(Get-TimeStamp)Creating resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
                }
                else{
                    Write-Verbose "$(Get-TimeStamp)Resource group already exists." #-ForegroundColor $([Constants]::MessageType.Info)
                }
                
            }
            catch
            {  
                Write-Host "`n`rFailed to create resource group for deployment." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }

            # Step 3: Create user-assigned MI resource. 
            Write-Host "Checking if user-assigned identity [$($UserAssignedIdentityName)] exists..." -ForegroundColor $([Constants]::MessageType.Info)            
            $UserAssignedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $UserAssignedIdentityName -ErrorAction SilentlyContinue
            if($UserAssignedIdentity -eq $null)
            {
                Write-Host "Creating a new user-assigned identity [$($UserAssignedIdentityName)]." -ForegroundColor $([Constants]::MessageType.Info)                
                $UserAssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $UserAssignedIdentityName
                Start-Sleep -Seconds 60
            }
            else
            {
                Write-Host "User-assigned identity [$($UserAssignedIdentityName)] already exists." -ForegroundColor $([Constants]::MessageType.Info)                            
            }
            
            # Grant User Identity Reader permission on target subscription(s).
            Write-Host "Granting user-assigned identity 'Reader' permission on target subscription(s)..." -ForegroundColor $([Constants]::MessageType.Info)         
            if( ($TargetSubscriptionIds | Measure-Object).Count -gt 0)
            {
                $TargetSubscriptionIds | % {
                    
                    try
                    {
                        Write-Host "Assigning 'Reader' access to user-assigned managed identity on target subscription [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                        New-AzRoleAssignment -ApplicationId $UserAssignedIdentity.ClientId -Scope "/subscriptions/$_" -RoleDefinitionName "Reader" -ErrorAction Stop
                    }
                    catch
                    {
                        if($_.Exception.Body.Code -eq "RoleAssignmentExists")
                        {
                            Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                            
                        }
                        else
                        {
                            Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                               
                        }
                    }
                }
            }
            else
            {
                Write-Host "No target subscription specified." -ForegroundColor $([Constants]::MessageType.Warning)            
            }       

            Write-Host "Completed Azure Tenant Security scanner identity setup." -ForegroundColor $([Constants]::MessageType.Info)

            Write-Host $([Constants]::SingleDashLine)    
            Write-Host ([constants]::ScanningIdentitySetupNextSteps) -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::DoubleDashLine)

            return $UserAssignedIdentity;
        }
        catch
        {
            Write-Host "Error occurred while setting up scanner identity. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;    
        }
    }
}



function AddAlert(

 [string] $Query,  
 [ValidateSet("Equal", "GreaterThan", "LessThan" )]
 [string] $ThresholdOperator,
 [int] $Threshold = 0,
 [string] $AlertDescription,
 [string] $AlertName,
 [ValidateSet(0,1,2,3,4)] 
 [int] $AlertSeverity = 2,
 [int] $FrequencyInMinutes = 5,
 [int] $TimeWindowInMinutes = 5,
 [string] $DataSourceId,
 [string] $ActionGroupResourceId,
 [string] $Location,
 [string] $ResourceGroupName 
 
 )
{
    $source = New-AzScheduledQueryRuleSource -Query $Query -DataSourceId $DataSourceId -WarningAction SilentlyContinue 
    $schedule = New-AzScheduledQueryRuleSchedule -FrequencyInMinutes $FrequencyInMinutes -TimeWindowInMinutes $TimeWindowInMinutes -WarningAction SilentlyContinue 
    $triggerCondition = New-AzScheduledQueryRuleTriggerCondition -ThresholdOperator $ThresholdOperator -Threshold $Threshold  -WarningAction SilentlyContinue
    $aznsActionGroup = New-AzScheduledQueryRuleAznsActionGroup -ActionGroup $ActionGroupResourceId -EmailSubject "TDMON ALERT: $($AlertName)" -WarningAction SilentlyContinue
    $alertingAction = New-AzScheduledQueryRuleAlertingAction -AznsAction $aznsActionGroup -Severity $AlertSeverity -Trigger $triggerCondition -WarningAction SilentlyContinue 
    
    
    # create alert
    New-AzScheduledQueryRule -ResourceGroupName $ResourceGroupName -Location $Location `
    -Action $alertingAction -Enabled $true `
    -Description $AlertDescription `
    -Schedule $schedule `
    -Source $source `
    -Name $AlertName -WarningAction SilentlyContinue
}