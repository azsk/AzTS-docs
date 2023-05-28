function Install-AzTSMMARemovalUtilitySolution {
    <#
	.SYNOPSIS
	    This command would help in installing MMA Removal Utility Solution in your subscription. 
	.DESCRIPTION
	    This command will install the MMA Removal Utility Solution which helps to discover and remove MMA agent installed on Virtual Machines.
	.PARAMETER SubscriptionId
		Subscription id in which MMA Removal Utility Solution needs to be installed.
	.PARAMETER HostRGName
		Name of ResourceGroup where setup resources will be created. 
	.PARAMETER Location
		Location where all resources will get created. Default location is EastUS2.
	.PARAMETER ManagedIdentityId
		Resource id of user managed identity used to scan subscriptions. 
    .PARAMETER TemplateFilePath
        Azure ARM template path used to deploy MMA Removal Utility Solution.
    .PARAMETER TemplateParameters
        Azure ARM template parameters used to deploy MMA Removal Utility Solution.
    .PARAMETER SendUsageTelemetry
        Usage telemetry captures anonymous usage data and sends it to Microsoft servers. This will help in improving the product quality and prioritize meaningfully on the highly used features.
	.LINK
	    https://aka.ms/azts-mmaremovalutility

	#>
    Param(
        
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Subscription id in which MMA Removal Utility Solution needs to be installed.")]
        [Parameter(Mandatory = $true, ParameterSetName = "MultiTenantSetup", HelpMessage = "Subscription id in which MMA Removal Utility Solution needs to be installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Name of ResourceGroup where setup resources will be created.")]
        [Parameter(Mandatory = $false, ParameterSetName = "MultiTenantSetup", HelpMessage = "Name of ResourceGroup where setup resources will be created.")]
        $HostRGName = "AzTS-MMARemovalUtility-Host-RG",

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Location where all resources will get created.")]
        [Parameter(Mandatory = $false, ParameterSetName = "MultiTenantSetup", HelpMessage = "Location where all resources will get created.")]
        $Location = "EastUS2",

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Resource id of user managed identity used to remediate subscriptions.")]
        [Parameter(Mandatory = $false, ParameterSetName = "MultiTenantSetup", HelpMessage = "Resource id of user managed identity used to remediate subscriptions.")]
        $ManagedIdentityId,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Application Id of central remediation identity.")]
        [Parameter(Mandatory = $true, ParameterSetName = "MultiTenantSetup", HelpMessage = "Application Id of central remediation identity.")]
        $IdentityApplicationId,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Key Vault SecretUri of the remediation App's Credential.")]
        [Parameter(Mandatory = $true, ParameterSetName = "MultiTenantSetup", HelpMessage = "Key Vault SecretUri of the remediation App's Credential.")]
        $IdentitySecretUri,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "MultiTenantSetup")]
        $TemplateFilePath = ".\MMARemovalUtilityDeploymentTemplate.bicep",

        [Hashtable]
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "MultiTenantSetup")]
        $TemplateParameters = @{},

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Azure environment in which MMA Removal Utility Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [Parameter(Mandatory = $false, ParameterSetName = "MultiTenantSetup", HelpMessage = "Azure environment in which MMA Removal Utility Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [ValidateSet("AzureCloud", "AzureGovernmentCloud")]
        $AzureEnvironmentName = "AzureCloud",

        [switch]
        [Parameter(Mandatory = $true, ParameterSetName = "MultiTenantSetup", HelpMessage = "Switch to enable multi-tenant scopes. Configurations required for multi-tenant remediation will be deployed.")]
        $SupportMultipleTenant,
        
        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Switch to mark if command is invoked through consolidated installation command. This will result in masking of few instrcution messages. Using this switch is not recommended while running this command in standalone mode.")]
        $ConsolidatedSetup = $false
    )
    Begin {
        $DisableUsageTelemetry = $true
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if (-not $currentContext) {
            return;
        }
    }

    Process {

        if ($ConsolidatedSetup -ne $true) {
            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Running MMA Removal Utility Solution setup..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Started setting up MMA Removal Utility Solution. This may take 5 mins..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
        }

        $deploymentResult = $null;
        $FunctionApps = $null;

        $ResourceId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $HostRGName;
        $ResourceIdHash = get-hash($ResourceId)
        $ResourceHash = $ResourceIdHash.Substring(0, 5).ToString().ToLower()
           
        try {
            [string] $OnboardingTenant = get-hash($context.Tenant.Id)
            [string] $OnboardingResourceGroupId = $ResourceIdHash.Substring(0, 16).ToString().ToLower()
            [string] $OnboardingOrg = [String]::Empty;
            [string] $OnboardingDiv = [String]::Empty;
            [string] $OnboardingContactEmail = [String]::Empty;
            [string] $AnonymousUsageTelemetryLogLevel = [String]::Empty;

            if ($DisableUsageTelemetry -eq $false) {               
                # Take acceptance from the user for the telemetry to be collected
                [string] $TelemetryAcceptanceMsg = "For the purpose of improving quality of AzTS MMA Removal solution and better customer service, the AzTS MMA Removal solution needs to collect the below mentioned data:`r`n`n" + 
                "   [1] Anonymized usage data -> this helps us improve product quality`r`n" +
                "   [2] Organization/team contact details -> these help us provide your team with:`r`n" +
                "                            [a] Updates about any feature change`r`n" +
                "                            [b] Support channel options (e.g., office hours)`r`n" +
                "                            [c] Occasional requests for feedback on specific features`r`n" +
                "You may choose to opt in or opt out of either or both of these by choosing Y/N at the prompts coming up. (Note that you can change your choice later too.)`r`n"

                Write-Host $TelemetryAcceptanceMsg -ForegroundColor $([Constants]::MessageType.warning)
                

                $AnonymousUsageCaptureFlag = Read-Host -Prompt "`n`rDo you wish to allow collection of anonymized usage data (Y/N)"
                if ($AnonymousUsageCaptureFlag -eq 'Y') {
                    $ContactDataCaptureFlag = Read-Host -Prompt "`n`Do you wish to Provide org/team contact info? (Y/N)"
                    if ($ContactDataCaptureFlag -eq 'Y') {
                        $AnonymousUsageTelemetryLogLevel = "Identifiable"

                        Write-Host "`n`rPlease provide details about your org, divison and team." -ForegroundColor $([Constants]::MessageType.warning)
                        $OnboardingOrg = Read-Host -Prompt "Organization Name"
                        $OnboardingDiv = Read-Host -Prompt "Division Name within your Organization"
                        $OnboardingContactEmail = Read-Host -Prompt "Contact DL to use for our communication"
                    }
                    else {
                        $AnonymousUsageTelemetryLogLevel = "Anonymous"
                    }
                }
                else {
                    $AnonymousUsageTelemetryLogLevel = "None"
                }

                $TemplateParameters.Add("AnonymousUsageTelemetryLogLevel", $AnonymousUsageTelemetryLogLevel)
                $TemplateParameters.Add("OrganizationName", $OnboardingOrg)
                $TemplateParameters.Add("DivisionName", $OnboardingDiv)
                $TemplateParameters.Add("ContactEmailAddressList", $OnboardingContactEmail)
                $TemplateParameters.Add("HashedTenantId", $OnboardingTenant)
                $TemplateParameters.Add("HashedResourceGroupId", $OnboardingResourceGroupId)
                
                Write-Host "`n`rThank you for your choices. To make changes to these preferences refer the FAQs by visiting https://aka.ms/azts-mmaremovalutility/UpdateTelemetryPreference." -ForegroundColor $([Constants]::MessageType.Update)
            }
                
        }
        catch {
            # Silently continue with installation.
        }

        # Create resource group if not exist
        try {
            Write-Verbose "$(Get-TimeStamp)Checking resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
            $rg = Get-AzResourceGroup -Name $HostRGName -ErrorAction SilentlyContinue
            if (-not $rg) {
                Write-Verbose "$(Get-TimeStamp)Creating resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                $rg = New-AzResourceGroup -Name $HostRGName -Location $Location -ErrorAction Stop
            }
            else {
                Write-Verbose "$(Get-TimeStamp)Resource group already exists." #-ForegroundColor $([Constants]::MessageType.Info)
            }
                
        }
        catch {  
            Write-Host "`n`rFailed to create resource group for deployment." -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
                    
        # Check if internal managed identity exist or create new one
        $InternalUserAssignedIdentityName = "MMARemovalUtility" + "-InternalMI-" + $ResourceHash
        Write-Host "Checking if user-assigned identity [$($InternalUserAssignedIdentityName)] for internal operations exists..." -ForegroundColor $([Constants]::MessageType.Info)            
        $UserAssignedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $HostRGName -Name $InternalUserAssignedIdentityName -ErrorAction SilentlyContinue
        if ($null -eq $UserAssignedIdentity) {
            Write-Host "Creating a new user-assigned identity [$($InternalUserAssignedIdentityName)]." -ForegroundColor $([Constants]::MessageType.Info)                
            $UserAssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $HostRGName -Name $InternalUserAssignedIdentityName -Location $Location
            Start-Sleep -Seconds 60
        }
        else {
            Write-Host "User-assigned identity [$($InternalUserAssignedIdentityName)] already exists." -ForegroundColor $([Constants]::MessageType.Info)                            
        }


        # Start bicep template deployment
        try {
                
            # Set up multi-tenant scan config (if enabled)
            $TemplateParameters.Add("ClientSecretUri", $IdentitySecretUri)
            $TemplateParameters.Add("ClientApplicationId", $IdentityApplicationId)
            if ($SupportMultipleTenant) {
                $TemplateParameters.Add("IsClientSecretAuthMode", $true)
                # If multi-tenat mode is enabled then Remediation Connection Secret URI must not be null
                if ([string]::IsNullOrWhiteSpace($IdentitySecretUri)) {
                    Write-Host "`n`rValue for parameter '-IdentitySecretUri' can not be null in multi-tenant setup." -ForegroundColor $([Constants]::MessageType.Error)
                    return;
                }

                # If multi-tenat mode is enabled then ApplicationId of remediation identity must not be null
                if ([string]::IsNullOrWhiteSpace($IdentityApplicationId)) {
                    Write-Host "`n`rValue for parameter '-IdentityApplicationId' can not be null in multi-tenant setup." -ForegroundColor $([Constants]::MessageType.Error)
                    return;
                }
            }
            else {
                $TemplateParameters.Add("IsClientSecretAuthMode", $false)
            }

            $TemplateParameters.Add("AzureEnvironmentName", $AzureEnvironmentName)
            # Get package version
                

            $CentralPackageInfo = [CentralPackageInfo]::new()

            $TemplateParameters.Add("ScopeResolverTriggerProcessorPackageUrl", $CentralPackageInfo.ScopeResolverTriggerProcessorPackageUrl)
            $TemplateParameters.Add("ScopeResolverProcessorPackageUrl", $CentralPackageInfo.ScopeResolverProcessorPackageUrl)
            $TemplateParameters.Add("ExtensionInventoryProcessorPackageUrl", $CentralPackageInfo.ExtensionInventoryProcessorPackageUrl)
            $TemplateParameters.Add("WorkItemSchedulerProcessorPackageUrl", $CentralPackageInfo.WorkItemSchedulerProcessorPackageUrl)
            $TemplateParameters.Add("ExtensionRemovalProcessorPackageUrl", $CentralPackageInfo.ExtensionRemovalProcessorPackageUrl)
            $TemplateParameters.Add("ExtensionRemovalStatusCheckProcessorPackageUrl", $CentralPackageInfo.ExtensionRemovalStatusCheckProcessorPackageUrl)
            
            #adding ResourceHash to TemplateParameters
            $TemplateParameters.Add("ResourceHash", $ResourceHash)
            $TemplateParameters.Add("MIResourceId", $ManagedIdentityId)
                
            #Get the tenant Id from the current subscription contex
            $context = Get-AzContext
            $TemplateParameters.Add("TenantId", $context.Tenant.Id)
            
            # Stop existing app services to unlock files; If any file is locked, deployment will fail
            $AppServices = Get-AzWebApp -ResourceGroupName $HostRGName 

            if ($null -ne $AppServices -and $AppServices.Count -gt 0) {
                $FunctionApps = $AppServices | Where-Object { $_.Kind -eq 'functionapp' }
            }

            # Stop function apps
            if ($null -ne $FunctionApps -and $FunctionApps.Count -gt 0) {
                Write-Verbose "$(Get-TimeStamp)Stopping function app(s) for deployment. This is required to unblock any file in use..."
                $stopppedApps = $FunctionApps | Stop-AzWebApp
                Write-Verbose "$(Get-TimeStamp)Stopped function app(s): $([string]::Join(", ", ($FunctionApps | Select-Object Name -Unique).Name))"
                    
            }

            Write-Verbose "$(Get-TimeStamp)Checking resource deployment template..." #-ForegroundColor $([Constants]::MessageType.Info)
                
            $validationResult = Test-AzResourceGroupDeployment -Mode Incremental -ResourceGroupName $HostRGName -TemplateFile $TemplateFilePath -TemplateParameterObject $TemplateParameters
            if ($validationResult) {
                Write-Host "`n`rTemplate deployment validation returned following errors:" -ForegroundColor $([Constants]::MessageType.Error)
                $validationResult | Format-List Code, Message | Out-String | Out-Host;
                return;
            }
            else {
                # Deploy template
                $deploymentName = "MMARemovalenvironmentsetup-$([datetime]::Now.ToString("yyyymmddThhmmss"))"
                $deploymentResult = New-AzResourceGroupDeployment -Name $deploymentName -Mode Incremental -ResourceGroupName $HostRGName -TemplateFile $TemplateFilePath -TemplateParameterObject $TemplateParameters  -ErrorAction Stop -verbose 
                Write-Verbose "$(Get-TimeStamp)Completed resources deployment for MMA Removal Utility Solution."
            }                
        }
        catch {
            Write-Host "`rTemplate deployment returned following errors: [$($_)]." -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
        finally {
            # Start app services if it was stopped before deployment
            if ($null -ne $FunctionApps -and $FunctionApps.Count -gt 0) {
                Write-Verbose "$(Get-TimeStamp)Starting function app(s)..."
                $startedApps = $FunctionApps | Start-AzWebApp
                Write-Verbose "$(Get-TimeStamp)Started function app(s): $([string]::Join(", ", ($FunctionApps | Select Name -Unique).Name))"
            }
        }
        # Post deployment steps
        Write-Verbose "$(Get-TimeStamp)Starting post deployment environment steps.." 
        try {

            # Deploy progress monitoring dashboard
            $dashboardName = "MMAAgentRemovalUtilityProgress-" + $ResourceHash;
            if ($deploymentResult.Outputs.ContainsKey('logAnalyticsResourceId')) {
                $dashboard = Set-AzTSMMARemovalUtilityMonitoringDashboard -SubscriptionId $SubscriptionId -ResourceGroupName $HostRGName -Location $Location -DashboardName $dashboardName -LAResourceId $deploymentResult.Outputs.logAnalyticsResourceId.Value -ConsolidatedSetup: $ConsolidatedSetup 
            }
            else {
                Write-Host "Skipped monitoring dashboard installation as Log Analytics workspace not deployed." -ForegroundColor $([Constants]::MessageType.Warning)
            }
            
            if ($ConsolidatedSetup -ne $true) {
                Write-Host "`rCompleted installation for MMA Removal Utility Solution." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "$([Constants]::DoubleDashLine)" #-ForegroundColor $([Constants]::MessageType.Info)
                Write-Host "$([Constants]::NextSteps -f $UIUrl)" -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host "$([Constants]::DoubleDashLine)"
            }
            else {
                Write-Host "`rCompleted installation for MMA Removal Utility Solution." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "$([Constants]::SingleDashLine)"
            }
        }
        catch {
            Write-Host "Error occurred while executing post deployment steps. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }

        return $deploymentResult
    }
}

function Set-AzTSMMARemovalUtilitySolutionRemediationIdentity {
    Param(
        
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which managed identity is to be created.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "Name of ResourceGroup where managed identity will be created.")]
        $ResourceGroupName = "AzTS-MMARemovalUtility-RG",

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Location where remediation identity will get created. Default location is EastUS2.")]
        $Location = "EastUS2",

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "Name of the Azure AD application to be used by the API.")]
        $UserAssignedIdentityName,

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage = "List of target subscription(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target subscription(s).")]
        $TargetSubscriptionIds = @(),

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage = "List of target management group(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target management group(s).")]
        $TargetManagementGroupNames = @(),

        [switch]
        [Parameter(Mandatory = $false, HelpMessage = "Switch to mark if command is invoked through consolidated installation command. This will result in masking of few instrcution messages. Using this switch is not recommended while running this command in standalone mode.")]
        $ConsolidatedSetup = $false,

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "TenantScope", HelpMessage = "Switch to enable MMA Removal Utility to run on tenant scope.")]
        $TenantScope
    )

    Begin {
        # Step 1: Set context to subscription where user-assigned managed identity needs to be created.
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if (-not $currentContext) {
            return;
        }
    }

    Process {
        try {

            if (-not $ConsolidatedSetup) {
                Write-Host $([Constants]::DoubleDashLine)
                Write-Host "Running MMA Removal utility identity setup..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            # Step 2: Create resource group where user-assigned MI resource will be created. 
            try {
                Write-Verbose "$(Get-TimeStamp)Checking resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
                if (-not $rg) {
                    Write-Verbose "$(Get-TimeStamp)Creating resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
                }
                else {
                    Write-Verbose "$(Get-TimeStamp)Resource group already exists." #-ForegroundColor $([Constants]::MessageType.Info)
                }
                
            }
            catch {  
                Write-Host "`n`rFailed to create resource group for deployment." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }

            # Step 3: Create user-assigned MI resource. 
            Write-Host "Checking if user-assigned identity [$($UserAssignedIdentityName)] exists..." -ForegroundColor $([Constants]::MessageType.Info)            
            $UserAssignedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $UserAssignedIdentityName -ErrorAction SilentlyContinue
            if ($null -eq $UserAssignedIdentity) {
                Write-Host "Creating a new user-assigned identity [$($UserAssignedIdentityName)]." -ForegroundColor $([Constants]::MessageType.Info)                
                $UserAssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $UserAssignedIdentityName -Location $Location
                Start-Sleep -Seconds 60
            }
            else {
                Write-Host "User-assigned identity [$($UserAssignedIdentityName)] already exists." -ForegroundColor $([Constants]::MessageType.Info)                            
            }
            
            # Grant User Identity Reader permission on target subscription(s).
            Write-Host "Granting user-assigned identity 'Reader' and 'Virtual Machine Contributor' permission on target scope(s)..." -ForegroundColor $([Constants]::MessageType.Info)         
            $targetSubscriptionCount = ($TargetSubscriptionIds | Measure-Object).Count
            $targetMgtGroupCount = ($TargetManagementGroupNames | Measure-Object).Count
            $assignmentError = $false
            if ($targetSubscriptionCount -gt 0) {
                $TargetSubscriptionIds | ForEach-Object {
                    try {
                        Write-Host "Assigning 'Reader' access to user-assigned managed identity on target subscription [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                        $roleAssignment = New-AzRoleAssignment -ApplicationId $UserAssignedIdentity.ClientId -Scope "/subscriptions/$_" -RoleDefinitionName "Reader" -ErrorAction Stop
                    }
                    catch {
                        if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                            Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                        }
                        else {
                            Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                            $assignmentError = true
                        }
                    }

                    try {
                        Write-Host "Assigning 'Virtual Machine Contributor' access to user-assigned managed identity on target subscription [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                        $roleAssignment = New-AzRoleAssignment -ApplicationId $UserAssignedIdentity.ClientId -Scope "/subscriptions/$_" -RoleDefinitionName "Virtual Machine Contributor" -ErrorAction Stop
                    }
                    catch {
                        if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                            Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                        }
                        else {
                            Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                            $assignmentError = true
                        }
                    }
                }
            }

            if ($TenantScope -eq $true)
            {
                $TargetManagementGroupNames += $"/providers/Microsoft.Management/managementGroups/$currentContext.Tenant.Id"
            }

            if ($targetMgtGroupCount -gt 0) {
                $TargetManagementGroupNames | ForEach-Object {
                    
                    try {
                        Write-Host "Assigning 'Reader' access to user-assigned managed identity on target management group [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                        $roleAssignment = New-AzRoleAssignment -ApplicationId $UserAssignedIdentity.ClientId -Scope "/providers/Microsoft.Management/managementGroups/$_" -RoleDefinitionName "Reader" -ErrorAction Stop
                    }
                    catch {
                        if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                            Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                            
                        }
                        else {
                            Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                            $assignmentError = true
                        }
                    }

                    try {
                        Write-Host "Assigning 'Virtual Machine Contributor' access to user-assigned managed identity on target subscription [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                        $roleAssignment = New-AzRoleAssignment -ApplicationId $UserAssignedIdentity.ClientId -Scope "/subscriptions/$_" -RoleDefinitionName "Virtual Machine Contributor" -ErrorAction Stop
                    }
                    catch {
                        if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                            Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                            
                        }
                        else {
                            Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                            $assignmentError = true
                        }
                    }
                }
            }
            
            if($assignmentError -eq $false)
            {
                Write-Host "Granted user-assigned identity 'Reader' and 'Virtual Machine Contributor' permission on target scope(s) successfully" -ForegroundColor $([Constants]::MessageType.Update)
            }
            
            if (-not(($targetSubscriptionCount -gt 0) -or ($targetMgtGroupCount -gt 0))) {
                Write-Host "No target subscription or management group or tenant scope specified." -ForegroundColor $([Constants]::MessageType.Warning)            
            }       

            Write-Host "Completed MMA Removal utility identity setup." -ForegroundColor $([Constants]::MessageType.Update)

            Write-Host $([Constants]::SingleDashLine)    
            Write-Host $([Constants]::DoubleDashLine)

            return $UserAssignedIdentity;
        }
        catch {
            Write-Host "Error occurred while setting up MMA Removal utility identity. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;    
        }
    }
}

function Set-AzTSMMARemovalUtilitySolutionScopes {
    Param(
        
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Subscription id in which MMA Removal Utility Solution is present.")]
        [Parameter(Mandatory = $true, ParameterSetName = "TenantScope", HelpMessage = "Subscription id in which MMA Removal Utility Solution is present.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Name of ResourceGroup where MMA Removal Utility Solution is present.")]
        [Parameter(Mandatory = $true, ParameterSetName = "TenantScope", HelpMessage = "Name of ResourceGroup where MMA Removal Utility Solution is present.")]
        $ResourceGroupName,

        [string[]]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "List of target subscription(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target subscription(s).")]
        $TargetSubscriptionIds = @(),

        [string[]]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "List of target management group(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target management group(s).")]
        $TargetManagementGroupNames = @(),

        [switch]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Switch to mark if command is invoked through consolidated installation command. This will result in masking of few instrcution messages. Using this switch is not recommended while running this command in standalone mode.")]
        $ConsolidatedSetup = $false,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "File path to enable multi-tenant scanning. Scope configurations required for multi-tenant scanning will be deployed.")]
        $ScopesFilePath,

        [switch]
        [Parameter(Mandatory = $true, ParameterSetName = "TenantScope", HelpMessage = "Switch to enable MMA Removal Utility to run on tenant scope")]
        $TenantScope
    )

    Begin {
        # Step 1: Set context to subscription where MMA Removal Utility Solution is present.
        $currentContext = $null

        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if (-not $currentContext) {
            return;
        }

        $TenantId = $currentContext.Tenant.Id
    }

    Process {
        try {

            if (-not $ConsolidatedSetup) {
                Write-Host $([Constants]::DoubleDashLine)
                Write-Host "Configuring MMA Removal utility scope(s)..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            # Step 2: Get resource group where MMA Removal Utility Solution is present.
            try {
                $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
                if (-not $rg) {
                    Write-Host "`n`rFailed to get resource group where MMA Removal Utility Solution is present." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "`n`rPlease re-check Subscription Id and Resource Group Name where MMA Removal Utility Solution is hosted." -ForegroundColor $([Constants]::MessageType.Error)
                    return;
                }
            }
            catch {  
                Write-Host "`n`rFailed to get resource group where MMA Removal Utility Solution is present." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }

            # Step 3:  Get Scope resolver trigger processor function app.

            $ResourceId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroupName;
            $ResourceIdHash = get-hash($ResourceId)
            $ResourceHash = $ResourceIdHash.Substring(0, 5).ToString().ToLower()
            $ScopeResolverTriggerAppName = "MMARemovalUtility-ScopeResolverTrigger-" + $ResourceHash

            Write-Host "Checking if ScopeResolverTriggerProcessor function app [$($ScopeResolverTriggerAppName)] exists..." -ForegroundColor $([Constants]::MessageType.Info)            
            $ScopeResolverTriggerApp = Get-AzWebApp -Name $ScopeResolverTriggerAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
            $scopeIndex = 0;
            if ($null -eq $ScopeResolverTriggerApp) {
                Write-Host "`n`rFailed to get ScopeResolverTriggerProcessor function app [$($ScopeResolverTriggerProcessorName)]." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "`n`rPlease re-check Subscription Id and Resource Group Name where MMA Removal Utility Solution is hosted." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }
            else {
                $configuredScopes = $ScopeResolverTriggerApp.SiteConfig.AppSettings | Where-Object { $_.Name -like 'ScopeResolverTriggerConfigurations__DiscoveryScopes__*' } 
                if (($configuredScopes | Measure-Object).Count -gt 0) {
                    $configuredScopeIds = $configuredScopes | Where-Object { $_.Name -like 'ScopeResolverTriggerConfigurations__DiscoveryScopes__*__ScopeId' } | Select-Object "Value"

                    [int32[]]$IndexCollection = @();
                    $configuredScopes | Select-Object "Name" | ForEach-Object {
                        $splitParts = $_.Name -split '__'
                        $IndexCollection += $splitParts[2]
                    }
                    
                    $IndexCollection = $IndexCollection | Sort-Object 
                    $scopeIndex = $IndexCollection[-1] + 1 
                }
            }
            
            $scopeObjects = @()
            

            # Grant User Identity Reader permission on target subscription(s).
            Write-Host "Configuring target scope(s)..." -ForegroundColor $([Constants]::MessageType.Info)         
            $targetSubscriptionCount = ($TargetSubscriptionIds | Measure-Object).Count
            $targetMgtGroupCount = ($TargetManagementGroupNames | Measure-Object).Count
            if ($targetSubscriptionCount -gt 0) {
                $TargetSubscriptionIds | ForEach-Object {

                    $scopeObject = "" | Select-Object "ScopeType", "ScopeId", "TenantId"
                    $scopeObject.ScopeType = "Subscription"
                    $scopeObject.ScopeId = $("/subscriptions/$_")
                    $scopeObject.TenantId = $TenantId
                    $scopeObjects += $scopeObject
                }
            }

            if ($targetMgtGroupCount -gt 0) {
                $TargetManagementGroupNames | ForEach-Object {
                    $scopeObject = "" | Select-Object "ScopeType", "ScopeId", "TenantId"
                    $scopeObject.ScopeType = "ManagementGroup"
                    $scopeObject.ScopeId = $("/providers/Microsoft.Management/managementGroups/$_")
                    $scopeObject.TenantId = $TenantId
                    $scopeObjects += $scopeObject
                }
            }
            
            if ($TenantScope) {
                $scopeObject = "" | Select-Object "ScopeType", "ScopeId", "TenantId"
                $scopeObject.ScopeType = "Tenant"
                $scopeObject.ScopeId = $TenantId
                $scopeObject.TenantId = $TenantId
                $scopeObjects += $scopeObject
            }

            if (-not [string]::IsNullOrWhiteSpace($ScopesFilePath) -and (Test-Path $ScopesFilePath -PathType Leaf)) {
                $scopesContent = Import-Csv -Path $ScopesFilePath
                if (($scopesContent | Measure-Object).Count -gt 0) {
                    $scopesContent | ForEach-Object {
                        $scopeObject = "" | Select-Object "ScopeType", "ScopeId", "TenantId"
                        $scopeObject.ScopeType = $_.ScopeType
                        $scopeObject.ScopeId = $_.ScopeId
                        $scopeObject.TenantId = $_.TenantId
                        $scopeObjects += $scopeObject
                    }
                }
            }

            if (($scopeObjects | Measure-Object).Count -eq 0) {
                Write-Host "No target subscription or management group specified." -ForegroundColor $([Constants]::MessageType.Warning)       
                return;     
            }    
            
            #setup the current app settings
            $settings = @{}
            ForEach ($setting in $ScopeResolverTriggerApp.SiteConfig.AppSettings) {
                $settings[$setting.Name] = $setting.Value
            }

            $duplicateScopeIds = @()
            $anyUniqueScopes = $false
            $scopeObjects | ForEach-Object {
                if ($configuredScopeIds.Value -contains $_.ScopeId) {
                    $duplicateScopeIds += $_.ScopeId
                }
                else {
                    #adding new settings to the app settigns
                    $anyUniqueScopes = $true
                    $settings[$("ScopeResolverTriggerConfigurations__DiscoveryScopes__{0}__ScopeType" -f $scopeIndex)] = $_.ScopeType;
                    $settings[$("ScopeResolverTriggerConfigurations__DiscoveryScopes__{0}__ScopeId" -f $scopeIndex)] = $_.ScopeId;
                    $settings[$("ScopeResolverTriggerConfigurations__DiscoveryScopes__{0}__TenantId" -f $scopeIndex)] = $_.TenantId;
                    $scopeIndex += 1;
                }
            }

            if (($duplicateScopeIds | Measure-Object).Count -gt 0) {
                Write-Host "Following duplicate scope(s) found, these scope(s) will be skipped:" -ForegroundColor $([Constants]::MessageType.Warning) 
                Write-Host $duplicateScopeIds 
            }

            # Update Scope resolver trigger procesor function app settings
            if ($anyUniqueScopes) {
                $app = Set-AzWebApp -Name $ScopeResolverTriggerAppName -ResourceGroupName $ResourceGroupName -AppSettings $settings
            }
            else {
                Write-Host "`r`nAll provided scope(s) as input are already present, no new scope(s) will be added.`r`n" -ForegroundColor $([Constants]::MessageType.Warning) 
            }

            if (-not $ConsolidatedSetup) {
                Write-Host "Completed MMA Removal utility scope(s) configuration." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)    
                Write-Host $([Constants]::DoubleDashLine)
                return; 
            }
            else {
                return $true;
            }
            
            
        }
        catch {
            Write-Host "Error occurred while configuring scope(s) for MMA Removal utility. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;    
        }
    }
}

function Set-AzTSMMARemovalUtilityMonitoringDashboard {
    Param(
        
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which monitoring dashboard is to be created.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "Name of ResourceGroup in which monitoring dashboard is to be created.")]
        $ResourceGroupName = "AzTS-MMARemovalUtility-Host-RG",

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "Location where monitoring dashboard is to be created. Default location is EastUS2.")]
        $Location = "EastUS2",

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "LA Resource Id which is to be associated to monitoring dashboard.")]
        $LAResourceId,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "Name of the Monitoring Dashboard. Default value is MMAAgentRemovalUtilityProgress")]
        $DashboardName = "MMAAgentRemovalUtilityProgress",

        [switch]
        [Parameter(Mandatory = $false, HelpMessage = "Switch to mark if command is invoked through consolidated installation command. This will result in masking of few instrcution messages. Using this switch is not recommended while running this command in standalone mode.")]
        $ConsolidatedSetup = $false
    )

    Begin {
        # Step 1: Set context to subscription and resource group where monitoring dashboard needs to be created.
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if (-not $currentContext) {
            return;
        }
    }

    Process {
        try {
            if (-not $ConsolidatedSetup) {
                Write-Host $([Constants]::DoubleDashLine)
                Write-Host "Running MMA Removal utility monitoring dashboard setup..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            # Step 2: Setting up monitoring dashboard.
            $Timespan = "7d"
            $ResourceId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroupName;
            $ResourceGroupIdHash = get-hash($ResourceId)
            $ResourceGroupIdHash = $ResourceGroupIdHash.Substring(0, 16).ToString().ToLower()
            $DashboardTemplatePath = ".\MMARemovalUtilityMonitoringDashboardTemplate.json"
            $DashboardTemplateReplacedPath = ".\MMARemovalUtilityMonitoringDashboardReplacedTemplate.json"
            $Content = Get-Content -Path $DashboardTemplatePath -Raw
            $Content = $Content -replace '<timespanValue>', $Timespan
            $Content = $Content -replace '<laResourceId>', $laResourceId
            $Content = $Content -replace '<location>', $location
            $Content = $Content -replace '<dashboardName>', $dashboardName
            $Content = $Content -replace '<azTSMMARemovalUtilityIdentifier>', $ResourceGroupIdHash
            $Content | Out-File -FilePath $DashboardTemplateReplacedPath -Force

            $DashboardParams = @{
                DashboardPath     = $DashboardTemplateReplacedPath
                ResourceGroupName = $ResourceGroupName
                DashboardName     = $DashboardName
                SubscriptionId    = $subscriptionId
            }

            Write-Host "Setting up monitoring dashboard [$($DashboardName)]..." -ForegroundColor $([Constants]::MessageType.Info)   

            $MonitoringDashboard = Set-AzPortalDashboard @DashboardParams   
            if (-not $ConsolidatedSetup) {
                Write-Host "Monitoring Dashboard [$($DashboardName)] successfully created." -ForegroundColor $([Constants]::MessageType.Update)  
                Write-Host $([Constants]::DoubleDashLine)
            }

            $DeletedFile = Remove-Item -Path $DashboardTemplateReplacedPath
        }
        catch {
            Write-Host "Error occurred while setting up MMA Removal Utility monitoring dashboard. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
    }
}
function Set-AzTSMMARemovalUtilitySolutionSecretStorage
{
    Param(
        
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription id in which key vault is to be created.")]
        $SubscriptionId,

        [string]
	    [Parameter(Mandatory = $true, HelpMessage="Name of ResourceGroup where key vault will be created.")]
	    $ResourceGroupName,

        [string]
        [Parameter(Mandatory = $false, HelpMessage="Location where the resource group and key vault will get created. Default location is EastUS2.")]
        $Location = "EastUS2",

        [string]
        [Parameter(Mandatory = $true, HelpMessage="Name of the Key Vault to be created.")]
        $KeyVaultName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="AzTS MMA Removal Utility Solution AAD Application's Password credentials.")]
        $AADAppPasswordCredential
    )

    Begin
    {
         # Step 1: Set context to subscription where key vault needs to be created.
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
            Write-Host "Running AzTS MMA Removal Utility Solution secret storage setup..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Step 2: Create resource group where KV resource will be created. 
            try
            {
                Write-Verbose "Checking resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
                if(-not $rg)
                {
                    Write-Verbose "Creating resource group for deployment..." #-ForegroundColor $([Constants]::MessageType.Info)
                    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
                }
                else{
                    Write-Verbose "Resource group already exists." #-ForegroundColor $([Constants]::MessageType.Info)
                }
                
            }
            catch
            {  
                Write-Host "`n`rFailed to create resource group for deployment." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }

            # Step 3: Deploy KV
            # Check if Key Vault already exist.

            $ResourceId='/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId,$ResourceGroupName;
            $ResourceIdHash = get-hash($ResourceId)
            $ResourceHash = $ResourceIdHash.Substring(0,5).ToString().ToLower()
            $KeyVaultName = "{0}-{1}" -f $KeyVaultName, $ResourceHash

            $keyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
            
            if ($null -ne $keyVault)
            {
                Write-Host "Key Vault already exist. All existing 'Access Policies' will be removed." -ForegroundColor $([Constants]::MessageType.Warning)
                $userChoice = Read-Host -Prompt "`n`Do you want to continue (Y/N)?"
                if ($userChoice -ne 'Y')
                {
                    Write-Host "Please provide another name to create new Key Vault. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                    return;
                }
                # Else continue with deployment
            }
            
            $secretName = "AzTSMMARemovalUtilityIdentityCredentials"
            $credentialSecureString = $AADAppPasswordCredential | ConvertTo-SecureString -AsPlainText -Force

            $validationResult = Test-AzResourceGroupDeployment -Mode Incremental `
                    -ResourceGroupName $ResourceGroupName  `
                    -TemplateFile ".\MMARemovalUtilityKeyVaultTemplate.bicep" `
                    -keyVaultName $KeyVaultName `
                    -secretName $secretName `
                    -secretValue $credentialSecureString `
                    -resourceHash $ResourceHash `
                    -location $Location
            if($validationResult)
            {
                Write-Host "`n`rTemplate deployment validation returned following errors:" -ForegroundColor $([Constants]::MessageType.Error)
                $validationResult | Format-List Code, Message | Out-String | Out-Host;
                return;
            }
            else
            {
                $deploymentName = "AzTSMMAenvironmentkeyvaultsetup-$([datetime]::Now.ToString("yyyymmddThhmmss"))"
                $deploymentOutput = New-AzResourceGroupDeployment -Name  $deploymentName `
                                                                -Mode Incremental `
                                                                -ResourceGroupName $ResourceGroupName  `
                                                                -TemplateFile ".\MMARemovalUtilityKeyVaultTemplate.bicep" `
                                                                -keyVaultName $KeyVaultName `
                                                                -secretName $secretName `
                                                                -secretValue $credentialSecureString `
                                                                -ResourceHash $ResourceHash `
                                                                -location $Location `

                Write-Host "Completed AzTS MMA Removal Utility Solution secret storage setup." -ForegroundColor $([Constants]::MessageType.Info)

                Write-Host $([Constants]::SingleDashLine)    
                Write-Host ([constants]::KeyVaultSecretStoreSetupNextSteps) -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::DoubleDashLine)

                return $deploymentOutput;
            }

        }
        catch
        {
            Write-Host "Error occurred while setting up secret storage. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;    
        }
    }
}

function Set-AzTSMMARemovalUtilitySolutionMultiTenantRemediationIdentity
{
    param (
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Display Name of the Remediation Identity.")]
        $displayName,

        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "PreExistApp", HelpMessage="Object Id of the Remediation Identity.")]
        $objectId,
        
        [string[]]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="UserPrinicipalNames of the additional owners for the App to be created.")]
        [Parameter(Mandatory = $false, ParameterSetName = "PreExistApp", HelpMessage="UserPrinicipalNames of the additional owners for the App to be created.")]
        $AdditionalOwnerUPNs = @()

    )
    try
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Running MMA Removal utility multi-tenant identity setup..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        $appDetails = "" | Select-Object "ApplicationId", "ObjectId", "Secret"
        if ([string]::IsNullOrWhiteSpace($objectId))
        {
            Write-Host "Checking if Azure AD application [$($displayName)] already exist..." -ForegroundColor $([Constants]::MessageType.Info)
            $aadApp = Get-AzureADApplication -SearchString $displayName
            if (!$aadApp) {

                Write-Host "Creating new AD application [$($displayName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                # create new application
                $aadApp = New-AzureADApplication -DisplayName $displayName -AvailableToOtherTenants $true
                Write-Host "Created [$($displayName)] app successfully." -ForegroundColor $([Constants]::MessageType.Update)
            }
            elseif(($aadApp | Measure-Object).Count -gt 1)
            {
                Write-Host "Multiple AD application with display name [$($displayName)] exists in AAD.`n Either choose different name to create new AAD app or provide Object Id of App as input to use existing App." -ForegroundColor $([Constants]::MessageType.error)
                return;
            }
            else
            {
                Write-Host "AD application [$($displayName)] already exists." -ForegroundColor $([Constants]::MessageType.Info)
            }

        }
        else
        {
            $aadApp = Get-AzureADApplication -ObjectId $objectId

            if(!$aadApp)
            {
                Write-Host "AD application with object Id [$($objectId)] not found in AAD." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }
            
        }

        # Create new password credential for App
        $startDateTime = Get-Date
        $endDateTime = $startDateTime.AddMonths(6)
        $pwdCredentials = New-AzureADApplicationPasswordCredential -ObjectId $aadApp.ObjectId -StartDate $startDateTime -EndDate $endDateTime
         
        # Adding additional owners (if any)
        if (($AdditionalOwnerUPNs| Measure-Object).Count -gt 0)
        {
            Add-OwnersToAADApplication -AppObjectId $aadApp.ObjectId -UserPrincipalNames $AdditionalOwnerUPNs
        }

        # Prepare output object 
        $appDetails.ApplicationId = $aadApp.AppId
        $appDetails.ObjectId = $aadApp.ObjectId
        $appDetails.Secret = $pwdCredentials.Value

        Write-Host $([Constants]::SingleDashLine)    
        Write-Host "Completed MMA Removal utility multi-tenant identity setup." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)

        return $appDetails
    }
    catch
    {
        if(($_.Exception | Get-Member ErrorContent -ErrorAction SilentlyContinue) -and ($_.Exception.ErrorContent | Get-Member Message -ErrorAction SilentlyContinue))
        {
            Write-Host "ErrorCode [$($_.Exception.ErrorCode)] ErrorMessage [$($_.Exception.ErrorContent.Message.Value)]"  -ForegroundColor $([Constants]::MessageType.Error)
        }
        else
        {
            Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

}

function Set-AzSKTenantSecuritySolutionMultiTenantIdentitySPN
{
  param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="unique identifier of the AAD application of which ServicePrincipal need to be created")]
        $AppId
    )
    try
    {

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Creating SPN for AzTS MMA Removal Utility Solution identity..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Checking if Azure AD service principal for App [$($AppId)] already exist..." -ForegroundColor $([Constants]::MessageType.Info)
        $spn = Get-AzureADServicePrincipal -Filter "AppId eq '$($AppId)'"
        if (!$spn) {

            Write-Host "Creating new Azure AD service principal for App [$($AppId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            # create new spn
            $spn = New-AzureADServicePrincipal -AppId $AppId -AppRoleAssignmentRequired $false 
            
            Write-Host $([Constants]::SingleDashLine)    
            Write-Host "Successfully created service principal." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            
        }
        else
        {
            Write-Host $([Constants]::SingleDashLine)    
            Write-Host "AD service principal for App [$($AppId)] already exists." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::DoubleDashLine)
        }

        # return spn object ($spn.ObjectId)
        return $spn
    }
    catch
    {
        if(($_.Exception | Get-Member ErrorContent -ErrorAction SilentlyContinue) -and ($_.Exception.ErrorContent | Get-Member Message -ErrorAction SilentlyContinue))
        {
            Write-Host "ErrorCode [$($_.Exception.ErrorCode)] ErrorMessage [$($_.Exception.ErrorContent.Message.Value)]"  -ForegroundColor $([Constants]::MessageType.Error)
        }
        else
        {
            Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
        }
    }
}

function Grant-AzSKAzureRoleToMultiTenantIdentitySPN
{
    Param(
        [string]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true,  HelpMessage="Object id of the identity used to remediate subscriptions.")]
        $AADIdentityObjectId,

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage="List of target subscription(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target subscription(s).")]
        $TargetSubscriptionIds = @(),

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage="List of target management group(s) from which MMA agent to be removed. Identity will be granted 'Reader' and 'Virtual Machine Contributor' access on target management group. Providing root management group name is recommended.")]
        $TargetManagementGroupNames = @()
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Granting required role permissions to service principal on target scope(s)..." -ForegroundColor $([Constants]::MessageType.Info) 
    Write-Host $([Constants]::SingleDashLine)
            
    $targetSubscriptionCount = ($TargetSubscriptionIds | Measure-Object).Count
    $targetMgtGroupCount = ($TargetManagementGroupNames | Measure-Object).Count
    if($targetSubscriptionCount -gt 0)
    {
        # Set Azure Context for first random subscription in current tenant
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($TargetSubscriptionIds[0])
        if(-not $currentContext)
        {
            return;
        }

        if ($targetSubscriptionCount -gt 0) {
            $TargetSubscriptionIds | ForEach-Object {
                
                try {
                    Write-Host "Assigning 'Reader' access to user-assigned managed identity on target subscription [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                    $roleAssignment = New-AzRoleAssignment -ObjectId $AADIdentityObjectId -Scope "/subscriptions/$_" -RoleDefinitionName "Reader" -ErrorAction Stop
                }
                catch {
                    if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                        Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                        
                    }
                    else {
                        Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                           
                    }
                }

                try {
                    Write-Host "Assigning 'Virtual Machine Contributor' access to user-assigned managed identity on target subscription [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                    $roleAssignment = New-AzRoleAssignment -ObjectId $AADIdentityObjectId -Scope "/subscriptions/$_" -RoleDefinitionName "Virtual Machine Contributor" -ErrorAction Stop
                }
                catch {
                    if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                        Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                        
                    }
                    else {
                        Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                           
                    }
                }
            }
        }

       
    }

    if ($targetMgtGroupCount -gt 0) {
        $TargetManagementGroupNames | ForEach-Object {
            
            try {
                Write-Host "Assigning 'Reader' access to user-assigned managed identity on target management group [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                $roleAssignment = New-AzRoleAssignment -ObjectId $AADIdentityObjectId -Scope "/providers/Microsoft.Management/managementGroups/$_" -RoleDefinitionName "Reader" -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                    Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                    
                }
                else {
                    Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                       
                }
            }

            try {
                Write-Host "Assigning 'Virtual Machine Contributor' access to user-assigned managed identity on target subscription [$($_)]" -ForegroundColor $([Constants]::MessageType.Info)                        
                $roleAssignment = New-AzRoleAssignment -ObjectId $AADIdentityObjectId -Scope "/subscriptions/$_" -RoleDefinitionName "Virtual Machine Contributor" -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                    Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                    
                }
                else {
                    Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                       
                }
            }
        }
    }



    if (-not(($targetSubscriptionCount -gt 0) -or ($targetMgtGroupCount -gt 0)))
    {
        Write-Host $([Constants]::SingleDashLine)    
        Write-Host "No target subscription or management group specified." -ForegroundColor $([Constants]::MessageType.Warning) 
        Write-Host $([Constants]::DoubleDashLine)
                   
    }
    else{
        Write-Host $([Constants]::SingleDashLine)    
        Write-Host "Completed role assignment(s) for service principal." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Add-AADApplicationOwners()
{
    Param(
        [string]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true,  HelpMessage="Object id of the Azure AD Application.")]
        $AppObjectId,

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage="List of owners to be added to an application.")]
        $OwnerObjectIds = @()
    )

    $allOwnerAdded = $true
    if (($OwnerObjectIds| Measure-Object).Count -gt 0)
    {
        $OwnerObjectIds | ForEach-Object{
            $objectId = $_
            try
            {
                Add-AzureADApplicationOwner -ObjectId $AppObjectId -RefObjectId $objectId
            }
            catch
            {
                $allOwnerAdded = $allOwnerAdded -and $false
                Write-Host "Error occurred while adding owner [ObjectId: $($objectId)] to application . ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
    }

    return $allOwnerAdded;

}

function Get-AADUserDetails()
{
    Param(
        [string[]]
        [Parameter(Mandatory = $false, HelpMessage="List of owners to be added to an application.")]
        $UserPrincipalNames  = @()
    )

    $aadUsers = @();
    if (($UserPrincipalNames| Measure-Object).Count -gt 0)
    {
        $UserPrincipalNames | ForEach-Object{
            $aadUser = "" | Select-Object "UPN", "ObjectId"
            $aadUser.UPN = $_;
            $aadUser.ObjectId  = [Constants]::AADUserNotFound
            try
            {
                $user = Get-AzureADUser -ObjectId $_
                $aadUser.ObjectId = $user.ObjectId
            }
            catch
            {
                Write-Host "Error occurred while fetching AAD user [UPN: $($aadUser.UPN)]. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
            }
            $aadUsers += $aadUser
        }
    }

    return $aadUsers;

}

function Add-OwnersToAADApplication()
{
    Param(
        [string]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true,  HelpMessage="Object id of the Azure AD Application.")]
        $AppObjectId,

        [string[]]
        [Parameter(Mandatory = $false, HelpMessage="List of owners to be added to an application.")]
        $UserPrincipalNames  = @()
    )

    Write-Host "Adding additional owners to AAD Application [App ObjectId: $($AppObjectId)]"

    if (($UserPrincipalNames|Measure-Object).Count -gt 0)
    {
        $aadUsers = Get-AADUserDetails -UserPrincipalNames $UserPrincipalNames
        $validAADUsers = $aadUsers | where-Object { $_.ObjectId -ne $([Constants]::UserNotFound)}

        if (($validAADUsers | Measure-Object).Count -gt 0)
        {
            $userObjectIds = $validAADUsers.ObjectId
            $allOwnersAdded = Add-AADApplicationOwners -AppObjectId $AppObjectId -OwnerObjectIds $userObjectIds

            if ($allOwnersAdded)
            {
                Write-Host "Owners for application added successfully." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else{
                Write-Host "One or more owners not added to application." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
        else{
            Write-Host "No valid users found."
        }
    }
    else
    {
        Write-Host "UserPrincipalNames is empty. No owners added to application."
    }
}

function Grant-AzTSMMARemediationIdentityAccessOnKeyVault
{
    Param
    (
        [string]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which Key Vault exist.")]
        [Parameter(Mandatory = $true, ParameterSetName = "EnableMonitoring", HelpMessage="Subscription id in which Key Vault exist.")]
        $SubscriptionId,

        [string]
		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Resource Id of existing Key Vault.")]
        [Parameter(Mandatory = $true, ParameterSetName = "EnableMonitoring", HelpMessage="Resource Id of existing Key Vault.")]
		$ResourceId,

        [string]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Object id of user managed identity.")]
        [Parameter(Mandatory = $true, ParameterSetName = "EnableMonitoring", HelpMessage="Object id of user managed identity.")]
        $UserAssignedIdentityObjectId,

        [string[]]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="User email Ids to whom monitoring alert mails should be sent.")]
        [Parameter(Mandatory = $true, ParameterSetName = "EnableMonitoring", HelpMessage="User email Ids to whom monitoring alert mails should be sent.")]
        $SendAlertsToEmailIds,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Key Vault SecretUri of the MMA Removal Utility solution App's credentials.")]
        [Parameter(Mandatory = $true, ParameterSetName = "EnableMonitoring", HelpMessage="Key Vault SecretUri of the MMA Removal Utility solution App's credentials.")]
        $IdentitySecretUri,

        [string]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="ResourceId of the LA Workspace to be associated with key vault.")]
        [Parameter(Mandatory = $true, ParameterSetName = "EnableMonitoring", HelpMessage="ResourceId of the LA Workspace to be associated with key vault.")]
        $LAWorkspaceResourceId,

        [switch]
        [Parameter(Mandatory = $true, ParameterSetName = "EnableMonitoring", HelpMessage="Switch to deploy alerts on top of Key Vault auditing logs.")]
        $DeployMonitoringAlert
    )

    try {

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Granting access over Key Valut to MI..." -ForegroundColor $([Constants]::MessageType.Info)        
        # Validate input
        # Check UserAssignedObject must be non null
        if([string]::IsNullOrWhiteSpace($UserAssignedIdentityObjectId)) 
        {
            Write-Host "Object Id of managed identity must not be null..." -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }


        #Set context to subscription where key vault exist
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if(-not $currentContext)
        {
            return;
        }
        
        # Check if Key Vault Exist
        $keyVault = Get-AzResource -ResourceId $ResourceId -ErrorAction SilentlyContinue

        if(-not $keyVault)
        {
            Write-Host "Unable to find any Key Vault with resourceId [$($ResourceId)] in subscription [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
        
        # Assigne Secret Get permission to MI
        Set-AzKeyVaultAccessPolicy -ResourceId $ResourceId -ObjectId $UserAssignedIdentityObjectId -PermissionsToSecrets get

        Write-Host "Successfully granted access over Key Valut to MI." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        if ($DeployMonitoringAlert -eq $true)
        {
            try{

                Write-Host "Creating monitoring alerts..." -ForegroundColor $([Constants]::MessageType.Info) 
                $EmailReceivers = @()
                $SendAlertsToEmailIds | ForEach-Object {
                    $EmailReceivers += New-AzActionGroupReceiver -Name "Notify_$($_)" -EmailReceiver -EmailAddress $_
                }

                $keyVaultRGName =  $ResourceId.Split("/")[4] # ResourceId is in format - /subscriptions/SubIdGuid/resourceGroups/RGName/providers/Microsoft.KeyVault/vaults/KeyVaultName
                $alertActionGroupForKV = Set-AzActionGroup -Name 'MMARemovalUtilityActionGroupForKV' -ResourceGroupName $keyVault.ResourceGroupName -ShortName 'MMAKVAlert' -Receiver $EmailReceivers -WarningAction SilentlyContinue

                $deploymentName = "MMARemovalenvironmentmonitoringsetupforkv-$([datetime]::Now.ToString("yyyymmddThhmmss"))"

                $alertQuery = [string]::Format([Constants]::UnintendedSecretAccessAlertQuery, $ResourceId, $IdentitySecretUri, $UserAssignedIdentityObjectId)
                $deploymentOutput = New-AzResourceGroupDeployment -Name  $deploymentName `
                                -Mode Incremental `
                                -ResourceGroupName $keyVaultRGName  `
                                -TemplateFile ".\MMARemovalUtilityKeyVaultMonitoringAlertTemplate.bicep" `
                                -UnintendedSecretAccessAlertQuery $alertQuery `
                                -ActionGroupId $alertActionGroupForKV.Id `
                                -LAResourceId $laWorkspaceResourceId `
                                -Location $keyVault.Location

               Write-Host "Completed monitoring alert setup." -ForegroundColor $([Constants]::MessageType.Update)

            }
            catch
            {
                if(($_.Exception | Get-Member ErrorContent -ErrorAction SilentlyContinue) -and ($_.Exception.ErrorContent | Get-Member Message -ErrorAction SilentlyContinue))
                {
                    Write-Host "ErrorCode [$($_.Exception.ErrorCode)] ErrorMessage [$($_.Exception.ErrorContent.Message.Value)]"  -ForegroundColor $([Constants]::MessageType.Error)
                }
                else
                {
                    Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
                }
            }

            Write-Host $([Constants]::SingleDashLine)    
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

function Set-AzTSMMARemovalUtilityRunbook {
    Param(      
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which automation account and key vault are present.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of the resource group in which automation account and key vault are present.")]
        $ResourceGroupName,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "Location where automation account should be created.")]
        $Location = "EastUS2",

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Location for which dynamic ip addresses should be allowed on keyvault. Default location is EastUS2.")]
        $FunctionAppUsageRegion,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Resource id of the keyvault on which ip addresses should be allowed.")]
        $KeyVaultResourceId
    )

    Begin {
        # Step 1: Set context to subscription and resource group where monitoring dashboard needs to be created.
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if (-not $currentContext) {
            return;
        }
    }

    Process {
        try {
            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Running MMA Removal utility runbook setup..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Step 2: Create Automation Account.
            $AutomationAccountName = "MMARemovalUtility-AutomationAccount-{0}"
            $ResourceId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroupName
            $ResourceIdHash = get-hash($ResourceId)
            $ResourceHash = $ResourceIdHash.Substring(0, 5).ToString().ToLower()
            $AutomationAccountName = $AutomationAccountName -f $ResourceHash 

            $DeploymentName = "AzTSMMAenvironmentautomationaccountsetup-$([datetime]::Now.ToString("yyyymmddThhmmss"))"
            $DeploymentOutput = New-AzResourceGroupDeployment -Name  $DeploymentName `
                -Mode Incremental `
                -ResourceGroupName $ResourceGroupName  `
                -TemplateFile ".\MMARemovalUtilityAutomationAccountTemplate.bicep" `
                -resourceHash $ResourceHash `
                -automationAccountName $AutomationAccountName `
                -location $Location

            Write-Host "Automation account [$($AutomationAccountName)] has been successfully created in the resource group [$($ResourceGroupName)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Step 3: Grant access for Automation Account System assigned managed identity on KeyVault.
            Write-Host "Assigning the identity on KeyVault..." -ForegroundColor $([Constants]::MessageType.Info)    
            $identity = $DeploymentOutput.Outputs.automationAccountManagedIdentity.Value
            Write-Host $([Constants]::SingleDashLine) 
            $identity
            Write-Host $([Constants]::SingleDashLine) 
            try {
                $roleAssignment = New-AzRoleAssignment -ObjectId $identity -Scope $KeyVaultResourceId -RoleDefinitionName "Key Vault Contributor" -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                    Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                            
                }
                else {
                    Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                               
                }
            }
           
            Write-Host "Assigned the identity on KeyVault successfully." -ForegroundColor $([Constants]::MessageType.Update)    
            Write-Host $([Constants]::SingleDashLine)

            # Step 4: Setup runbook.
            $RunbookName = 'UpdateDynamicIPAddresses'
            Write-Host "Setting the runbook [$($RunbookName)] in the automation account [$($AutomationAccountName)]..." -ForegroundColor $([Constants]::MessageType.Info)    
            
            $UpdateDynamicIPAddressesScriptFilePath = ".\MMARemovalUtilityUpdateDynamicIPAddresses.ps1"
            $UpdateDynamicIPAddressesScriptModifiedFilePath = ".\MMARemovalUtilityUpdateDynamicIPAddressesModified.ps1"
            $RemoveExistingIPRanges = $true

            $Content = Get-Content -Path $UpdateDynamicIPAddressesScriptFilePath -Raw
            $Content = $Content -replace '<SubscriptionId>', $SubscriptionId
            $Content = $Content -replace '<KeyVaultResourceId>', $KeyVaultResourceId
            $Content = $Content -replace '<FunctionAppUsageRegion>', $FunctionAppUsageRegion
            $Content = $Content -replace '<RemoveExistingIPRanges>', $RemoveExistingIPRanges
            $Content | Out-File -FilePath $UpdateDynamicIPAddressesScriptModifiedFilePath -Force

            $runbook = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -Path $UpdateDynamicIPAddressesScriptModifiedFilePath -Published -Type PowerShell -Force
            Start-Sleep -Seconds 10
            Write-Host "Runbook [$($RunbookName)] has been successfully created in the automation account [$($AutomationAccountName)]." -ForegroundColor $([Constants]::MessageType.Update)
            $DeletedFile = Remove-Item -Path $UpdateDynamicIPAddressesScriptModifiedFilePath
            Write-Host $([Constants]::SingleDashLine)

            # Step 5: Triggering runbook.
            Write-Host "Triggering the runbook [$($RunbookName)] in the automation account [$($AutomationAccountName)]..." -ForegroundColor $([Constants]::MessageType.Info)   
            $TriggerRunbook = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName
            Write-Host "Runbook [$($RunbookName)] has been successfully triggered in the automation account [$($AutomationAccountName)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Step 6: Setup the recurring schedule for running the script every week.
            [System.DayOfWeek[]]$WeekDays = @([System.DayOfWeek]::Monday)
            $ScheduleName = "UpdateDynamicIPAddressesScheduleRecurring"
            Write-Host "Setting up the recurring schedule for [$($RunbookName)] in the automation account [$($AutomationAccountName)]..." -ForegroundColor $([Constants]::MessageType.Info)   
            $CreateSchedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ScheduleName -StartTime $(Get-Date).AddMinutes(6) -WeekInterval 1 -DaysOfWeek $WeekDays
            Start-Sleep -Seconds 10
            $RegisterSchedule = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName -ScheduleName $ScheduleName
            Write-Host "Recurring schedule for [$($RunbookName)] has been successfully created in the automation account [$($AutomationAccountName)]." -ForegroundColor $([Constants]::MessageType.Update)                            
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while setting up MMA Removal Utility runbook. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
    }
}

function Set-Prerequisites {
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
        "Az.Accounts" = "2.12.1";
        "Az.Resources" = "6.5.1";
        "Az.ManagedServiceIdentity" = "0.7.3";
        "Az.Monitor" = "1.5.0";
        "Az.OperationalInsights" = "1.3.4";
        "Az.ApplicationInsights" = "1.0.3";
	    "Az.Portal" = "0.1.0";
        "AzureAD" = "2.0.2.140";
        "Az.KeyVault" = "4.9.0";
        "Az.Automation" = "1.9.1";
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


# Helper classes and methods
function get-hash([string]$textToHash) {
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash.ToLower())
    $hashByteArray = $hasher.ComputeHash($toHash)
    $result = [string]::Empty;
    foreach ($byte in $hashByteArray) {
        $result += "{0:X2}" -f $byte
    }
    return $result;
}

function Get-TimeStamp {
    return "{0:h:m:ss tt} - " -f (Get-Date -UFormat %T)
}

class ContextHelper {
    $currentContext = $null;

    [PSObject] SetContext([string] $SubscriptionId) {
        $this.currentContext = $null
        if (-not $SubscriptionId) {

            Write-Host "The argument 'SubscriptionId' is null. Please specify a valid subscription id." -ForegroundColor $([Constants]::MessageType.Error)
            return $null;
        }

        # Login to Azure and set context
        try {
            if (Get-Command -Name Get-AzContext -ErrorAction Stop) {
                $this.currentContext = Get-AzContext -ErrorAction Stop
                $isLoginRequired = (-not $this.currentContext) -or (-not $this.currentContext | GM Subscription) -or (-not $this.currentContext | GM Account)
                    
                # Request login if context is empty
                if ($isLoginRequired) {
                    Write-Host "No active Azure login session found. Initiating login flow..." -ForegroundColor $([Constants]::MessageType.Warning)
                    $this.currentContext = Connect-AzAccount -ErrorAction Stop # -SubscriptionId $SubscriptionId
                }
            
                # Switch context if the subscription in the current context does not the subscription id given by the user
                $isContextValid = ($this.currentContext) -and ($this.currentContext | GM Subscription) -and ($this.currentContext.Subscription | GM Id)
                if ($isContextValid) {
                    # Switch context
                    if ($this.currentContext.Subscription.Id -ne $SubscriptionId) {
                        $this.currentContext = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
                    }
                }
                else {
                    Write-Host "Invalid PS context. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            else {
                Write-Host "Az command not found. Please run the following command 'Install-Module Az -Scope CurrentUser -Repository 'PSGallery' -AllowClobber -SkipPublisherCheck' to install Az module." -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        catch {
            Write-Host "Error occurred while logging into Azure. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return $null;
        }

        return $this.currentContext;
    
    }
    
}

class Constants {
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [string] $InstallSolutionInstructionMsg = "This command will perform following important operations. It will:`r`n`n" + 
    "   [1] Create resources needed to support AzTS MMA Removal Utility `r`n" +
    "   [2] Deploy packages to azure function app `r`n" +
    "   [3] Schedule daily discovery and removal schedules `r`n" +
    "   [4] Deploy monitoring dashboard to view progress `r`n" +
    "More details about resources created can be found in the link: http://aka.ms/AzTS/MMARemovalUtility `r`n"

    static [string] $QuickInstallSolutionInstructionMsg = "This command will perform following major steps. It will:`r`n`n" + 
    "   [0] Validate and install required Az modules (Optional) `r`n" +
    "   [1] Setup central remediation managed identity `r`n" +
    "   [2] Create resources needed to support AzTS MMA Removal Utility `r`n" +
    "   [3] Deploy packages to azure function app `r`n" +
    "   [4] Schedule daily discovery and removal schedules `r`n" +
    "   [5] Deploy monitoring dashboard to view progress `r`n" +
    "More details about resources created can be found in the link: http://aka.ms/AzTS/MMARemovalUtility `r`n"

    static [string] $DoubleDashLine = "================================================================================"
    static [string] $SingleDashLine = "--------------------------------------------------------------------------------"
    
    static [string] $NextSteps = "** Next steps **`r`n" + 
    "        a) AzTS MMA Removal Utility discovery phase will start on scheduled time (UTC 01:00).`r`n" +
    "        b) After scan completion, all Subscriptions/Virtual Machines/VM Extensions inventory will be available in LA workspace.`r`n" +
    "        c) Using the Monitoring dashboard, you can view the progress and numbers of VMs which are eligible for Removal phase (VMs having both MMA and AMA agent are considered for Removal phase).`r`n" +
    "`r`nFor any feedback contact us at: azsksup@microsoft.com.`r`n"

    static [string] $KeyVaultSecretStoreSetupNextSteps = "** Next steps **`r`n" + 
    "Run the command 'Install-AzTSMMARemovalUtilitySolution' to setup AzTS Removal Utility. Later continue with 'Grant-AzTSMMARemediationIdentityAccessOnKeyVaulty' command to grant remediation identity access over secret stored in Key Vault.`r`n";
    
    static [string] $AADUserNotFound = "UserNotFound";

    static [string] $UnintendedSecretAccessAlertQuery = "
                                        let TablePlaceholder = view () {{ print IdentityObjectId = 'NA', Count = '0' }};
                                        let secretAccessEvent = union isfuzzy=true TablePlaceholder, (union (
                                        AzureDiagnostics
                                        | where ResourceId =~ '{0}'
                                        | where OperationName =~ 'SecretGet'
                                        | where requestUri_s contains '{1}'
                                        | where isnotempty(identity_claim_oid_g) and identity_claim_oid_g !~ '{2}'
                                        | summarize Count = count() by IdentityObjectId =  tostring(identity_claim_oid_g)))
                                        | where IdentityObjectId <> 'NA';
                                        secretAccessEvent"

}

class CentralPackageInfo {
    [string] $ScopeResolverTriggerProcessorPackageUrl = [string]::Empty
    [string] $ScopeResolverProcessorPackageUrl = [string]::Empty
    [string] $ExtensionInventoryProcessorPackageUrl = [string]::Empty
    [string] $WorkItemSchedulerProcessorPackageUrl = [string]::Empty
    [string] $ExtensionRemovalProcessorPackageUrl = [string]::Empty
    [string] $ExtensionRemovalStatusCheckProcessorPackageUrl = [string]::Empty

    CentralPackageInfo() {
        $this.ScopeResolverTriggerProcessorPackageUrl = "https://aka.ms/AzTS/MMARemovalUtility/ScopeResolverTriggerProcessorPackage"
        $this.ScopeResolverProcessorPackageUrl = "https://aka.ms/AzTS/MMARemovalUtility/ScopeResolverProcessorPackage"
        $this.ExtensionInventoryProcessorPackageUrl = "https://aka.ms/AzTS/MMARemovalUtility/ExtensionInventoryProcessorPackage"
        $this.WorkItemSchedulerProcessorPackageUrl = "https://aka.ms/AzTS/MMARemovalUtility/WorkItemSchedulerProcessorPackage"
        $this.ExtensionRemovalProcessorPackageUrl = "https://aka.ms/AzTS/MMARemovalUtility/ExtensionRemovalProcessorPackage"
        $this.ExtensionRemovalStatusCheckProcessorPackageUrl = "https://aka.ms/AzTS/MMARemovalUtility/ExtensionRemovalStatusCheckProcessorPackage"
    }

}

class Logger{
    [string] $logFilePath = "";

    Logger([string] $HostSubscriptionId)
    {
        $logFolerPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\MMARemovalUtilitySetup\Subscriptions\$($HostSubscriptionId.replace('-','_'))";
        $logFileName = "\$('DeploymentLogs_' + $(Get-Date).ToString('yyyyMMddhhmm') + '.txt')";
        $this.logFilePath = $logFolerPath + $logFileName
        # Create folder if not exist
        if (-not (Test-Path -Path $logFolerPath))
        {
            New-Item -ItemType Directory -Path $logFolerPath | Out-Null
        }
        # Create log file
        
        New-Item -Path $this.logFilePath -ItemType File | Out-Null
        
    }

    PublishCustomMessage ([string] $message, [string] $foregroundColor){
       $($message) | Add-Content $this.logFilePath -PassThru | Write-Host -ForegroundColor $foregroundColor
    }

    PublishCustomMessage ([string] $message){
       $($message) | Add-Content $this.logFilePath -PassThru | Write-Host -ForegroundColor White
    }

    PublishLogMessage ([string] $message){
        $($message) | Add-Content $this.logFilePath
    }

    PublishLogFilePath()
    {
        Write-Host $([Constants]::DoubleDashLine)"`r`nLogs have been exported to: $($this.logFilePath)`r`n"$([Constants]::DoubleDashLine) -ForegroundColor Cyan
    }
}
