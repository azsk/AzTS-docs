function Install-AzSKTenantSecuritySolutionConsolidated
{
    <#
	.SYNOPSIS
	This command would help in installing Azure Tenant Security Solution in your subscription. 
	.DESCRIPTION
	This command will installing all components of Azure Tenant Security Solution which runs security scan on subscription in a Tenant.
	Security scan results will be populated in Log Analytics workspace and Azure Storage account which is configured during installation.  
	
	.PARAMETER ScanningIdentityHostSubId
		Subscription id in which scanner identity (MI) is to be created.
	.PARAMETER ScanningIdentityHostRGName
		Name of ResourceGroup where scanner identity (MI) will be created. 
	.PARAMETER ScanningIdentityName
		Name of the scanning identity (MI) to be used by the scanner.
	.PARAMETER SubscriptionId
		Subscription id in which Azure Tenant Security Solution needs to be installed.
	.PARAMETER ScanHostRGName
		Name of ResourceGroup where setup resources will be created. 
	.PARAMETER SubscriptionsToScan
		List of subscription(s) to be scanned by Azure Tenant Security scanning solution. 
	.PARAMETER ManagementGroupsToScan
		List of target management group(s) to be scanned by Azure Tenant Security scanning solution. 
	.PARAMETER GrantGraphPermissionToScanIdentity
		Switch to grant Graph permission to scanning identity.
	.PARAMETER GrantGraphPermissionToInternalIdentity
		Specify if internal managed identity to be granted Graph permission. 
	.PARAMETER ScanIdentityHasGraphPermission
		Specify if user managed identity has Graph permission. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission. 
	.PARAMETER SetupAzModules
		Switch to validate required modules. If passed command will check needed modules with required version, will install required modules if not available in the system. 
	.PARAMETER Location
		Location where all resources will get created. Default location is EastUS2.
	.PARAMETER SendAlertNotificationToEmailIds
		Email ids to which alert notification should be sent.
	.PARAMETER EnableVnetIntegration
		Switch to enable vnet integration. Resources required for vnet setup will be deployed only if this switch is ON.
	.PARAMETER EnableAutoUpdater
		Switch to enable AzTS auto updater. Autoupdater helps to get latest feature released for AzTS components covering updates for security controls.
	.PARAMETER EnableAzTSUI
		Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan.
	.PARAMETER EnableWAF
		Switch to enable WAF. Resources required for implementing WAF will be deployed only if this switch is ON.
    .PARAMETER TemplateFilePath
        Azure ARM template path used to deploy Azure Tenant Security Solution.
    .PARAMETER TemplateParameters
        Azure ARM template parameters used to deploy Azure Tenant Security Solution.
    .PARAMETER SendUsageTelemetry
        Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.
    .PARAMETER CentralStorageAccountConnectionString
        Connection string of the storage account to be used to store the scan logs centrally.
    .NOTES
	

	.LINK
	https://aka.ms/azts-docs

	#>

    Param(

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which scanner identity is to be created.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Subscription id in which scanner identity is to be created.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Subscription id in which scanner identity is to be created.")]
        $ScanningIdentityHostSubId,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Name of ResourceGroup where scanner identity will be created.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Name of ResourceGroup where scanner identity will be created.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Name of ResourceGroup where scanner identity will be created.")]
        $ScanningIdentityHostRGName,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Name of the scanning identity to be used by the scanner.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Name of the scanning identity to be used by the scanner.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Name of the scanning identity to be used by the scanner.")]
        $ScanningIdentityName,

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

        [string[]]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="List of subscription(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target subscription.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="List of subscription(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target subscription.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="List of subscription(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target subscription.")]
        [Alias("SubscriptionsToScan")]
        $TargetSubscriptionIds = @(),

        [string[]]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="List of target management group(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target management group. Providing root management group name is recommended.")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="List of target management group(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target management group. Providing root management group name is recommended.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="List of target management group(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target management group. Providing root management group name is recommended.")]
        [Alias("ManagementGroupsToScan")]
        $TargetManagementGroupNames = @(),

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Specify to grant Graph permission to scanning identity. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="Specify to grant Graph permission to scanning identity. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Specify to grant Graph permission to scanning identity. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        $GrantGraphPermissionToScanIdentity = $false,

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Specify if internal managed identity to be granted Graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="Specify if internal managed identity to be granted Graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Specify if internal managed identity to be granted Graph permission.")]
        $GrantGraphPermissionToInternalIdentity = $false,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default",  HelpMessage="Location where all resources and scanner MI will get created. Default location is EastUS2.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI",  HelpMessage="Location where all resources and scanner MI will get created. Default location is EastUS2.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility",  HelpMessage="Location where all resources and scanner MI will get created. Default location is EastUS2.")]
        $Location = 'EastUS2',

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
        [Parameter(Mandatory = $false,  ParameterSetName = "Default", HelpMessage="Switch to validate required modules. If passed command will check needed modules with required version, will install required modules if not available in the system.")]
        [Parameter(Mandatory = $false,  ParameterSetName = "AzTSUI", HelpMessage="Switch to validate required modules. If passed command will check needed modules with required version, will install required modules if not available in the system.")]
        [Parameter(Mandatory = $false,  ParameterSetName = "CentralVisibility", HelpMessage="Switch to validate required modules. If passed command will check needed modules with required version, will install required modules if not available in the system.")]
        $SetupAzModules = $false,

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Specify if user managed identity has Graph permission. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "AzTSUI", HelpMessage="Specify if user managed identity has Graph permission. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Specify if user managed identity has Graph permission. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission.")]
        $ScanIdentityHasGraphPermission = $false,

        [string[]]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Email ids to which alert notification should be sent.")]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Email ids to which alert notification should be sent.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Email ids to which alert notification should be sent.")]
        [Alias("SREEmailIds")]
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
        [Alias("EnableAutoUpdates")]
        $EnableAutoUpdater,

        [switch]
        [Parameter(Mandatory = $true, ParameterSetName = "AzTSUI", HelpMessage="Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralVisibility", HelpMessage="Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan.")]
        $EnableAzTSUI,

        [switch]
        [Parameter(Mandatory = $false, HelpMessage="Switch to enable WAF. Resources required for implementing WAF will be deployed only if this switch is ON.")]
        $EnableWAF = $false,
        
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralVisibility", HelpMessage="Connection string of the storage account to be used to store the scan logs centrally.")]
        [Alias("StorageAccountConnectionString")]
        $CentralStorageAccountConnectionString
    )

    Begin
    {
        $inputParams = $PSBoundParameters
        # Load AzTS Setup script in session
        . ".\AzTSSetup.ps1"
        # Get logger instance
        $logger = [Logger]::new($SubscriptionId)
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine + "`r`nMethod Name: Install-AzSKTenantSecuritySolutionConsolidated `r`nInput Parameters: $(($inputParams | Out-String).TrimEnd()) `r`n"), $([Constants]::MessageType.Info)) 
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
        $logger.PublishCustomMessage("Starting Azure Tenant Security Solution installation. This may take 5 mins...", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($($([Constants]::QuickInstallSolutionInstructionMsg)), $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine))

        if ($SetupAzModules)
        {
            $logger.PublishCustomMessage($([Constants]::SingleDashLine))
            $logger.PublishCustomMessage("**Step 0**: Validate prerequisites.", $([Constants]::MessageType.Info))
            $logger.PublishCustomMessage($([Constants]::SingleDashLine))
            $allPrerequisiteMet = Setup-Prerequisites

            if (-not $allPrerequisiteMet)
            {
                $logger.PublishCustomMessage("One or more required Az modules are missing. AzTS setup will be skipped.", $([Constants]::MessageType.Error))
                break;
            }
            else
            {
                $logger.PublishLogMessage("All required modules are available.")
            }

        }


        # Disconnect from current AD/Azure session
        try
        {
            #Disconnect-AzAccount
            #Disconnect-AzureAD
        }
        catch
        {
            # If user is not already connected to Azure, Disconnect command will return an error. In this case, please ignore the error and continue to next step. 
        }

        # Connect to AzureAD and AzAccount
        #Connect-AzAccount -Tenant $HostTenantId
        #Connect-AzureAD -TenantId $HostTenantId

        ##############################################################################
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("**Step 1.A**: Set up scanning identity.", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("Setting up Azure Tenant Security scanner identity...`n", $([Constants]::MessageType.Info))
        # Step 1: Setting up scanning identity  
        # 1- Create scanner MI and grant 'Reader' permission on target subscriptions.
        $UserAssignedIdentity = Set-AzSKTenantSecuritySolutionScannerIdentity -SubscriptionId $ScanningIdentityHostSubId `
                                                                                -ResourceGroupName $ScanningIdentityHostRGName `
                                                                                -Location $Location `
                                                                                -UserAssignedIdentityName $ScanningIdentityName `
                                                                                -TargetSubscriptionIds $TargetSubscriptionIds `
                                                                                -TargetManagementGroupNames $TargetManagementGroupNames `
                                                                                -ConsolidatedSetup

        if ([string]::IsNullOrWhiteSpace($UserAssignedIdentity))
        {
            # No need to log Error message, it's done by the above command itself
            # If UserAssignedIdentity is null stop script execution, as it represent error occurred while setting up scanner identity
            $logger.PublishLogMessage("Error occurred while setting up scanning identity.")
            $logger.PublishLogFilePath()
            return;
        }
        else
        {
            $logger.PublishLogMessage("Resource id and principal Id generated for user identity:`r`nPrincipalId: $($UserAssignedIdentity.PrincipalId) `r`nResourceId: $($UserAssignedIdentity.Id) `r`n$([Constants]::DoubleDashLine)")
        }

        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("**Step 1.B**: Grant Graph permissions to scanning identity.", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))

        $graphPermissionGranted = $false
        if ($GrantGraphPermissionToScanIdentity -eq $true)
        {
            try{
                Grant-AzSKGraphPermissionToUserAssignedIdentity -UserAssignedIdentityObjectId $UserAssignedIdentity.PrincipalId -MSGraphPermissionsRequired @("PrivilegedAccess.Read.AzureResources", "Directory.Read.All") -ADGraphPermissionsRequired @("Directory.Read.All")
                $graphPermissionGranted = $true
                $logger.PublishLogMessage("Graph permissions granted to scanning identity.")
            }
            catch{
                $graphPermissionGranted = $false
                $logger.PublishLogMessage("Error occurred while granting Graph permissions to scanning identity.")
            }
        }
        else
        {
            $graphPermissionGranted = $false
            $logger.PublishCustomMessage("Skipped: Graph permissions not granted to scanner identity.",  $([Constants]::MessageType.Warning))
            $logger.PublishCustomMessage($($([constants]::ScanningIdentitySetupNextSteps)), $([Constants]::MessageType.Info))
            $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        }

        # ***** Initialize required parameters ******

        # Subscription id in which Azure Tenant Security Solution needs to be installed.
        $HostSubscriptionId = $SubscriptionId 

        # Specify if scanner MI has Graph permission. This is to exclude controls dependent on Graph API reponse from the scan result, if scanner identity does not have graph permission.
        # Users can choose to either grant Graph permission in consoliadted command itself (use -GrantGraphPermissionToScanIdentity) or Grant manually (and pass -ScanIdentityHasGraphPermission switch)
        $ScanIdentityHasGraphPermission = $graphPermissionGranted -or $ScanIdentityHasGraphPermission

        ##############################################################################

        # Step 2: Create Azure AD application for secure authentication 
        # Setup AD application for AzTS UI and API
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("**Step 2**: Setup AD application for AzTS UI and API.", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))

        if ($EnableAzTSUI -eq $true)
        {
            $ADApplicationDetails = Set-AzSKTenantSecurityADApplication -SubscriptionId $HostSubscriptionId -ScanHostRGName $ScanHostRGName -ConsolidatedSetup

            if ($ADApplicationDetails -eq $null)
            {
                # No need to log Error message, it's done by the above command itself
                # If ADApplicationDetails is null stop script execution, as it represent error occurred while setting up AD App
                $logger.PublishLogFilePath()
                return;
            }
            else
            {
                # Else $ADApplicationDetails object contains UI & Web API AD App details
                $logger.PublishLogMessage("App Id of UI & Web API Azure AD Applications:`r`WebAPIAzureADAppId: $($ADApplicationDetails.WebAPIAzureADAppId) `r`nUIAzureADAppId: $($ADApplicationDetails.UIAzureADAppId) `r`n$([Constants]::DoubleDashLine)")
            }
            
        }
        else{
            $logger.PublishCustomMessage("Skipped: This step has been skipped as AzTS UI is not enabled for the setup.", $([Constants]::MessageType.Warning))
            $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        }
        
        ##############################################################################
        # Step 3. Set context and deploy AzTS resources in Host RG and Subscription ****
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("**Step 3.A**: Install AzTS setup.", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("Started setting up Azure Tenant Security Solution..." ,$([Constants]::MessageType.Info))
        # Set the context to hosting subscription
        $azContext = Set-AzContext -SubscriptionId  $HostSubscriptionId

        # Invoke install solution command 
        $CommandArguments = @{
                            SubscriptionId = $HostSubscriptionId
                            ScanHostRGName = $ScanHostRGName
                            Location = $Location
                            ScanIdentityId = $UserAssignedIdentity.Id 
                            AzureEnvironmentName = $AzureEnvironmentName
                            SendAlertNotificationToEmailIds  = $SendAlertNotificationToEmailIds
                            TemplateFilePath = $TemplateFilePath
                            TemplateParameters = $TemplateParameters
                            SendUsageTelemetry = $SendUsageTelemetry
                            ScanIdentityHasGraphPermission = $ScanIdentityHasGraphPermission
                            EnableAutoUpdater = $EnableAutoUpdater 
                            EnableVnetIntegration = $EnableVnetIntegration
                            EnableWAF = $EnableWAF
                            ConsolidatedSetup = $true
                        }

        if ($EnableAzTSUI -eq $true)
        {
            $CommandArguments += @{
                EnableAzTSUI = $true
                WebAPIAzureADAppId = $ADApplicationDetails.WebAPIAzureADAppId
                UIAzureADAppId = $ADApplicationDetails.UIAzureADAppId
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($CentralStorageAccountConnectionString))
        {
            $CommandArguments.Add('CentralStorageAccountConnectionString', $CentralStorageAccountConnectionString)
        }

        $DeploymentResult = Install-AzSKTenantSecuritySolution @CommandArguments

        if ((($DeploymentResult | Measure-Object).Count -eq 0) -or (($DeploymentResult.Outputs | Measure-Object).Count -eq 0))
        {
            # No need to log Error message in console, it's done by the above command itself
            # If deployment result is null stop script execution, as it represent error occurred while deploying AzTS resources
            $logger.PublishLogMessage("Error occurred during deployment of AzTS components in subscription.")
            $logger.PublishLogFilePath()
            return;
        }

        # Save internal user-assigned managed identity name generated using below command. This will be used to grant Graph permission to internal MI.
        $InternalIdentityObjectId = $DeploymentResult.Outputs.internalMIObjectId.Value
        $logger.PublishLogMessage("Internal MI Object Id: $($InternalIdentityObjectId)")
        $logger.PublishLogMessage("Deployment of AzTS components completed.")
        
        $deploymentOutputs = $DeploymentResult.Outputs | ConvertTo-Json | ConvertFrom-Json

        $logger.PublishCustomMessage($([Constants]::DoubleDashLine))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("**Step 3.B**: Grant internal MI required Graph permissions.", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))

        # Grant internal MI 'User.Read.All' permission.
        if ($GrantGraphPermissionToInternalIdentity -eq $true)
        {
            # No need for exception handling, present in command itself
            Grant-AzSKGraphPermissionToUserAssignedIdentity `
                    -UserAssignedIdentityObjectId  $InternalIdentityObjectId  `
                    -MSGraphPermissionsRequired @('User.Read.All')
           
        }
        else
        {
            $logger.PublishCustomMessage("Skipped: Graph permissions not granted to internal MI identity.", $([Constants]::MessageType.Warning))
            $logger.PublishCustomMessage($($([constants]::InternalIdentitySetupNextSteps)),$([Constants]::MessageType.Info))
            $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        }

        $UIUrl = [string]::Empty

        if($EnableAzTSUI -and $deploymentOutputs.PSObject.Properties.Name.Contains("uiAppName"))
        {
            $azureUIAppName= $DeploymentResult.Outputs.uiAppName.Value
            $UIUrl =  $([string]::Concat($([string]::Format($AzureEnvironmentAppServiceURI.$AzureEnvironmentName, $azureUIAppName)), "/"))
        }
        
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine))
        if($EnableAzTSUI -and $EnableWAF)
        {
            $AzTSUIFrontDoorUrl = $DeploymentResult.Outputs.azTSUIFrontDoorUrl.Value
            $logger.PublishCustomMessage("$([Constants]::NextSteps -f $AzTSUIFrontDoorUrl)", $([Constants]::MessageType.Info));
            $logger.PublishCustomMessage("IMPORTANT: AzTS UI will be available only after completing 'step a' listed under Next steps. AzTS UI URL for your tenant: $($AzTSUIFrontDoorUrl)", $([Constants]::MessageType.Warning))
        }
        elseif($EnableAzTSUI)
        {
            $logger.PublishCustomMessage("$([Constants]::NextSteps -f $UIUrl)", $([Constants]::MessageType.Info))
            $logger.PublishCustomMessage("IMPORTANT: AzTS UI will be available only after completing 'step a' listed under Next steps. AzTS UI URL for your tenant: $($UIUrl)", $([Constants]::MessageType.Warning))
        }
        else 
        {
            $logger.PublishCustomMessage("$([Constants]::NextSteps -f $UIUrl)", $([Constants]::MessageType.Info))
        }
        $logger.PublishLogFilePath()

        return $DeploymentResult

    }
}

function Setup-Prerequisites {
    <#
        .SYNOPSIS
        Checks if all required Az modules are present, else, sets them up.
        .DESCRIPTION
        Checks if all required Az modules are present, else, sets them up.
        Includes installing any required Azure modules.
        .INPUTS
        None. You cannot pipe objects to Setup-Prerequisites.
        .OUTPUTS
        Boolean. 'True' if all pre-requisites are met 'False' otherwise.
        .EXAMPLE
        PS> Setup-Prerequisites
        .LINK
        None
    #>
    $allPrerequisiteMet = $true
    # List of required modules
    $requiredModules = @{
        "Az.Accounts" = "2.9.0";
        "Az.Resources" = "1.10.0";
        "Az.Storage" = "2.0.0";
        "Az.ManagedServiceIdentity" = "0.7.3";
        "Az.Monitor" = "1.5.0";
        "Az.OperationalInsights" = "1.3.4";
        "Az.ApplicationInsights" = "1.0.3";
        "Az.Websites" = "2.8.1";
        "Az.Network"  = "2.5.0";
        "Az.FrontDoor" = "1.8.0";
	"Az.CosmosDB" = "1.8.2";
        "AzureAD" = "2.0.2.130";
    }

    $requiredModuleNames = @()
    $requiredModules.Keys | ForEach-Object { $requiredModuleNames += $_.ToString()}

    try{

        Write-Host "Checking if all required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
        $availableModules = $(Get-Module -ListAvailable $requiredModuleNames -ErrorAction Stop) | Select-Object Name, Version | Sort-Object -Property "Version" -Descending

        # Check if the required modules are installed.
        $installedModules = @()
        $missingModules = @()
        $requiredModules.Keys | ForEach-Object {
            $requiredModule = "" | Select-Object "Name", "RequiredVersion"
            $requiredModule.RequiredVersion = $requiredModules[$_]
            $requiredModule.Name = $_
            $modulePresent =  $availableModules | Where-Object {($_.Name -eq $requiredModule.Name) -and ($_.Version -ge $requiredModule.RequiredVersion)} | Select-Object -First 1
            if ($modulePresent)
            {
                $installedModules += $requiredModule
            }
            else
            {
                $missingModules += $requiredModule
            }
        }

        if (($missingModules | Measure-Object).Count -eq 0)
        {
            $allPrerequisiteMet = $true
            Write-Host "All required modules are present." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Installing missing modules..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "Following modules (with required version) are not present:" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $($missingModules | FT | Out-String) -ForegroundColor $([Constants]::MessageType.Info)

            $userChoice = Read-Host -Prompt "Do you want to install all missing modules (Y/N)"
            if ($userChoice -eq "Y")
            {
                $missingModules |  ForEach-Object {
                    Write-Host "Installing $($_.Name) module..." -ForegroundColor $([Constants]::MessageType.Info)
                    Install-Module -Name $_.Name -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop -Force
                    if ($?)
                    {
                        $allPrerequisiteMet = $allPrerequisiteMet -and $true
                        Write-Host "Successfully installed $($_.Name) module." -ForegroundColor $([Constants]::MessageType.Update)
                    }
                    else
                    {
                        $allPrerequisiteMet = $allPrerequisiteMet -and $false
                        Write-Host "Unable to install $($_.Name) module." -ForegroundColor $([Constants]::MessageType.Warning)
                    }
                }
                
            }
            else
            {
                $allPrerequisiteMet = $false
                Write-Host "Module installation skipped based on user's choice." -ForegroundColor $([Constants]::MessageType.Info)
            }
        }
    }
    catch
    {
        $allPrerequisiteMet = $false
    }
    
    return $allPrerequisiteMet;
}
