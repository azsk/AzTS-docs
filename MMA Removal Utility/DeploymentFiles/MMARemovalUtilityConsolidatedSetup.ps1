function Install-AzTSMMARemovalUtilitySolutionConsolidated {
    <#
	.SYNOPSIS
	    This command would help in installing MMA Removal Utility Solution in your subscription. 
	.DESCRIPTION
	    This command will install an MMA Removal Utility Solution which helps to discover and remove MMA agent installed on Virtual Machines.
    .PARAMETER RemediationIdentityHostSubId
		Subscription id in which remediation identity (MI) is to be created.
	.PARAMETER RemediationIdentityHostRGName
		Name of ResourceGroup where remediation identity (MI) will be created. 
	.PARAMETER RemediationIdentityName
		Name of the remediation identity (MI) to be used by the MMA Removal Utility.
	.PARAMETER SubscriptionId
		Subscription id in which MMA Removal Utility Solution needs to be installed.
	.PARAMETER HostRGName
		Name of ResourceGroup where setup resources will be created. 
	.PARAMETER Location
		Location where all resources will get created. Default location is EastUS2. 
    .PARAMETER TemplateFilePath
        Azure ARM template path used to deploy MMA Removal Utility Solution.
    .PARAMETER TemplateParameters
        Azure ARM template parameters used to deploy MMA Removal Utility Solution.
    .PARAMETER DisableUsageTelemetry
        When DisableUsageTelemetry switch is not used, usage telemetry captures usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.
	.LINK
	    https://aka.ms/azts-mmaremovalutility
	#>
    Param(
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Subscription id in which remediation identity for MMA Removal Utility Solution is to be created.")]
        [Parameter(Mandatory = $true, ParameterSetName = "TenantScope", HelpMessage = "Subscription id in which remediation identity for MMA Removal Utility Solution is to be created.")]
        $RemediationIdentityHostSubId,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Name of ResourceGroup where remediation identity for MMA Removal Utility Solution will be created.")]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope", HelpMessage = "Name of ResourceGroup where remediation identity for MMA Removal Utility Solution will be created.")]
        $RemediationIdentityHostRGName = 'AzTS-MMARemovalUtility-RG',

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Name of the remediation identity to be used by the MMA Removal Utility Solution.")]
        [Parameter(Mandatory = $true, ParameterSetName = "TenantScope", HelpMessage = "Name of the remediation identity to be used by the MMA Removal Utility Solution.")]
        $RemediationIdentityName,

        [string[]]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "List of target subscription(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target subscription(s).")]
        $TargetSubscriptionIds = @(),

        [string[]]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "List of target management group(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target management group(s).")]
        $TargetManagementGroupNames = @(),

        [switch]
        [Parameter(Mandatory = $true, ParameterSetName = "TenantScope", HelpMessage = "Switch to enable MMA Removal Utility to run on tenant scope")]
        $TenantScope,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Subscription id in which MMA Removal Utility Solution needs to be installed.")]
        [Parameter(Mandatory = $true, ParameterSetName = "TenantScope", HelpMessage = "Subscription id in which MMA Removal Utility Solution needs to be installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Name of ResourceGroup where setup resources will be created.")]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope", HelpMessage = "Name of ResourceGroup where setup resources will be created.")]
        $HostRGName = "AzTS-MMARemovalUtility-Host-RG",

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Location where all resources will get created. Default location is EastUS2.")]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope", HelpMessage = "Location where all resources will get created. Default location is EastUS2.")]
        $Location = "EASTUS2",

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope")]
        $TemplateFilePath = ".\MMARemovalUtilityDeploymentTemplate.bicep",

        [Hashtable]
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope")]
        $TemplateParameters = @{},

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.")]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope", HelpMessage = "Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.")]
        $DisableUsageTelemetry = $false,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Azure environment in which MMA Removal Utility Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope", HelpMessage = "Azure environment in which MMA Removal Utility Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [ValidateSet("AzureCloud", "AzureGovernmentCloud")]
        $AzureEnvironmentName = "AzureCloud",

        [switch]
        [Parameter(Mandatory = $false,  ParameterSetName = "Default", HelpMessage="Switch to validate required modules. If passed command will check needed modules with required version, will install required modules if not available in the system.")]
        [Parameter(Mandatory = $false,  ParameterSetName = "TenantScope", HelpMessage="Switch to validate required modules. If passed command will check needed modules with required version, will install required modules if not available in the system.")]
        $SetupAzModules = $false

    )
    Begin {
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($RemediationIdentityHostSubId)
        if (-not $currentContext) {
            return;
        }
    }

    Process {

        $inputParams = $PSBoundParameters
        # Load AzTS Setup script in session
        . ".\MMARemovalUtilitySetup.ps1"
        # Get logger instance
        $logger = [Logger]::new($SubscriptionId)
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine + "`r`nMethod Name: Install-MMARemovalUtilitySolutionConsolidated  `r`nInput Parameters: $(($inputParams | Out-String).TrimEnd()) `r`n"), $([Constants]::MessageType.Info)) 
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
        $logger.PublishCustomMessage("Starting AzTS MMA Removal Utility Solution installation. This may take 5-10 mins...", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($($([Constants]::QuickInstallSolutionInstructionMsg)), $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::DoubleDashLine))
        
        ##############################################################################
        # Step 0: Validate and install required Az modules  
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

        ##############################################################################
        # Step 1: Setting up remediation identity  
        # 1- Create remediation MI and grant 'Reader' and 'VM Contributor' permission on target subscriptions.
        $logger.PublishCustomMessage("**Step 1**: Set up managed identity to discover/remove MMA agent.", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("Setting up AzTS MMA Removal Utility Solution identity...`n", $([Constants]::MessageType.Info))

        if ($TenantScope -eq $true)
        {
            $TargetManagementGroupNames += $"/providers/Microsoft.Management/managementGroups/$currentContext.Tenant.Id"
        }

        $UserAssignedIdentity = Set-AzTSMMARemovalUtilitySolutionRemediationIdentity -SubscriptionId $RemediationIdentityHostSubId `
                                                                                -ResourceGroupName $RemediationIdentityHostRGName `
                                                                                -Location $Location `
                                                                                -UserAssignedIdentityName $RemediationIdentityName `
                                                                                -TargetSubscriptionIds $TargetSubscriptionIds `
                                                                                -TargetManagementGroupNames $TargetManagementGroupNames `
                                                                                -ConsolidatedSetup

        if ([string]::IsNullOrWhiteSpace($UserAssignedIdentity))
        {
            # No need to log Error message, it's done by the above command itself
            # If UserAssignedIdentity is null stop script execution, as it represent error occurred while setting up remediation identity
            $logger.PublishLogMessage("Error occurred while setting up remediation identity.")
            $logger.PublishLogFilePath()
            return;
        }
        else
        {
            $logger.PublishLogMessage("Resource id and principal Id generated for user identity:`r`nPrincipalId: $($UserAssignedIdentity.PrincipalId) `r`nResourceId: $($UserAssignedIdentity.Id) `r`n$([Constants]::DoubleDashLine)")
        }

        ##############################################################################
        # Step 2. Set context and deploy AzTS resources in Host RG and Subscription ****

        $logger.PublishCustomMessage("**Step 2**: Install AzTS MMA Removal Utility Solution setup.", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("Started setting up AzTS MMA Removal Utility Solution..." ,$([Constants]::MessageType.Info))
        # Set the context to hosting subscription
        $azContext = Set-AzContext -SubscriptionId  $SubscriptionId

        # Invoke install solution command 
        $CommandArguments = @{
            SubscriptionId = $SubscriptionId
            HostRGName = $HostRGName
            Location = $Location
            ManagedIdentityId = $UserAssignedIdentity.Id 
            AzureEnvironmentName = $AzureEnvironmentName
            TemplateFilePath = $TemplateFilePath
            TemplateParameters = $TemplateParameters
            DisableUsageTelemetry = $DisableUsageTelemetry
            ConsolidatedSetup = $true
        }

        $DeploymentResult = Install-AzTSMMARemovalUtilitySolution @CommandArguments

        if ((($DeploymentResult | Measure-Object).Count -eq 0) -or (($DeploymentResult.Outputs | Measure-Object).Count -eq 0))
        {
            # No need to log Error message in console, it's done by the above command itself
            # If deployment result is null stop script execution, as it represent error occurred while deploying AzTS resources
            $logger.PublishLogMessage("Error occurred during deployment of AzTS MMA Removal Utility Solution components in subscription.")
            $logger.PublishLogFilePath()
            return;
        }

        $logger.PublishLogMessage("Deployment of AzTS components completed.")

        ##############################################################################
        # Step 3. Set required discovery scopes in scope resolver trigger processor.
        $logger.PublishCustomMessage("**Step 3**: Configure MMA Removal utility scope(s).", $([Constants]::MessageType.Info))
        $logger.PublishCustomMessage($([Constants]::SingleDashLine))
        $logger.PublishCustomMessage("Started setting up MMA Removal utility scope(s)..." ,$([Constants]::MessageType.Info))

        if ($TenantScope -eq $true)
        {
            $CommandArguments = @{
                SubscriptionId = $SubscriptionId
                ResourceGroupName = $HostRGName
                TenantScope = $TenantScope
            }
        }
        else
        {
            $CommandArguments = @{
                SubscriptionId = $SubscriptionId
                ResourceGroupName = $HostRGName
                TargetSubscriptionIds = $TargetSubscriptionIds
                TargetManagementGroupNames = $TargetManagementGroupNames
                ConsolidatedSetup = $true
            }
        }
        

        $response = Set-AzTSMMARemovalUtilitySolutionScopes @CommandArguments

        if ($response)
        {
            $logger.PublishCustomMessage("Completed MMA Removal utility scope(s) configuration.", $([Constants]::MessageType.Info))
            $logger.PublishCustomMessage("$([Constants]::NextSteps -f $UIUrl)", $([Constants]::MessageType.Info))
        }
        else {
            $logger.PublishLogMessage("Error occurred while configuring MMA Removal utility scope(s).")
        }

        $logger.PublishCustomMessage($([Constants]::SingleDashLine))

        $logger.PublishLogFilePath()

        return $DeploymentResult
    }
}


