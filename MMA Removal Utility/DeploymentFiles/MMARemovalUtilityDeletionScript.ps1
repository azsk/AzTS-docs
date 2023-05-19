function Remove-AzTSMMARemovalUtilitySolutionResources
{
    Param(
        [string]
        [Parameter(ParameterSetName = "DeleteResourceGroup", Mandatory = $true, HelpMessage="Subscription id from which AzTS MMA Removal Utility solution resoure group will be deleted.")]
        [Parameter(ParameterSetName = "DeleteResources", Mandatory = $true, HelpMessage="Subscription id from which AzTS MMA Removal Utility solution resources will be deleted.")]
        $SubscriptionId,

        [string]
        [Parameter(ParameterSetName = "DeleteResourceGroup", Mandatory = $true, HelpMessage="Name of ResourceGroup which will be deleted.")]
        [Parameter(ParameterSetName = "DeleteResources", Mandatory = $true, HelpMessage="Name of ResourceGroup from which AzTS MMA Removal Utility solution resources will be deleted.")]
        $ResourceGroupName,

        [switch]
        [Parameter(ParameterSetName = "DeleteResourceGroup", Mandatory = $true, HelpMessage="Boolean flag to delete entire resource group of AzTS MMA Removal Utility solution resources.")]
        $DeleteResourceGroup,

        [switch]
        [Parameter(ParameterSetName = "DeleteResources", Mandatory = $false, HelpMessage="Boolean flag to exclude log analytics workspace and application insights while deletion of AzTS MMA Removal Utility solution resources.")]
        $KeepInventoryAndProcessLogs
    )

    Begin
    {   
        # Load AzTS Setup script in session
        . ".\MMARemovalUtilitySetup.ps1"

        # Step 1: Set context to subscription and resource group where monitoring dashboard needs to be created.
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
            # Step 2: Get resource group from which MMA Utility resources will be deleted. 
            try
            {
                Write-Verbose "Getting resource group from which AzTS MMA Removal Utility solution resources will be deleted..."
                Get-AzResourceGroup -Name $ResourceGroupName
            }
            catch
            {  
                Write-Host "`n`rFailed to get resource group with the input name [$($ResourceGroupName)]." -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }

            Write-Host "Validating whether the current user [$($currentContext.Account.Id)] has the required permissions to run the script for resource group [$($ResourceGroupName)]..."
            
            # Safe Check: Checking whether the current account is of type User.
            if($currentContext.Account.Type -ne "User")
            {
                Write-Host "WARNING: This script can only be run by the user account type." -ForegroundColor $([Constants]::MessageType.Warning)
                break;
            }

            # Step 3: Retrieve role assignments on the resource group and verify if user has required permissions.

            # Safe Check: Current user should have Owner permission on the resource group.
            try
            {
                $userRoleAssignmentsOnRG = Get-AzRoleAssignment -SignInName $currentContext.Account.Id -ResourceGroupName $ResourceGroupName -IncludeClassicAdministrators;

                if(($userRoleAssignmentsOnRG | Where-Object { $_.RoleDefinitionName -eq "Owner"} | Measure-Object).Count -le 0)
                {
                    Write-Host "WARNING: User should have Owner permission to perform deletion activity." -ForegroundColor $([Constants]::MessageType.Warning)
                    break;
                }
                else
                {
                    Write-Host "User has the required permissions for to run the script." -ForegroundColor $([Constants]::MessageType.Update)
                }
            }
            catch
            {  
                Write-Host "`n`rFailed to validate user permissions on the resource group [$($ResourceGroupName)]. " -ForegroundColor $([Constants]::MessageType.Error)
                return;
            }


            # Step 4: Delete the resources/resource group based on the user preference.
            if($DeleteResourceGroup -eq $true)
            {
                try
                {
                    Write-Host "Deleting the resource group [$($ResourceGroupName)]..."
                    $success = Remove-AzResourceGroup -Name $ResourceGroupName -Force
                    if(-not $success)
                    {
                        Write-Host "Deletion of the resource group [$($ResourceGroupName)] was not successful." -ForegroundColor $([Constants]::MessageType.Update)
                    }
                    else
                    {
                        Write-Host "Resource group [$($ResourceGroupName)] has been successfully deleted." -ForegroundColor $([Constants]::MessageType.Update)
                    }
                }
                catch
                {  
                    Write-Host "`n`rFailed to delete the resource group [$($ResourceGroupName)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    return;
                }
            }
            else
            {
                $rgHash = get-hash('/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroupName)
                $rgHashId = $rgHash.Substring(0, 16).ToString().ToLower()
                
                try
                {
                    Write-Verbose "Getting resources from the resource group [$($ResourceGroupName)]..."
                    $resources = Get-AzResource -ResourceGroupName $ResourceGroupName -Tag @{"AzTSMMARemovalUtilityIdentifier" = $rgHashId}
                }
                catch
                {  
                    Write-Host "`n`rFailed to get resources from the resource group [$($ResourceGroupName)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    return;
                }

                if (($resources | Measure-Object).Count -gt 0)
                {
                    Write-Host "Found the below resources associated with AzTS MMA Removal Utility solution." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)	

                    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
                                    @{Expression = { $_.ResourceType }; Label = "ResourceType"; Width = 60; Alignment = "left" },
                                    @{Expression = { $_.Location }; Label = "Location"; Width = 30; Alignment = "left" }

                    $resources | Format-Table -Property $colsProperty -Wrap

                    Write-Host "Do you want to continue with deletion of the above resource(s) from the resource group [$($ResourceGroupName)]? " -ForegroundColor $([Constants]::MessageType.Warning)

                    $userInput = Read-Host -Prompt "(Y|N)"

                    if ($userInput -ne "Y") {
                        Write-Host "AzTS MMA Removal Utility solution resources will not be deleted from the Resource Group [$($ResourceGroupName)]. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                        return
                    }
                    else
                    {
                        Write-Host "Deleting the above resource(s) from the resource group [$($ResourceGroupName)]..."
                    }

                    $failedResources = @()
                    $failedRoleAssignments = @()
                    
                    $resources | ForEach-Object {
                        $resource = $_
                        
                        try 
                        {
                            if ($KeepInventoryAndProcessLogs -eq $true -and ($resource.Type -eq "Microsoft.OperationalInsights/workspaces" -or $resource.Type -eq "microsoft.insights/components"))
                            {
                                return
                            }

                            # Skippig deletion of server farms explicitly, will be cleanup as part of the app deletion.
                            if ($resource.Type -eq "Microsoft.Web/serverfarms")
                            {
                                return
                            }

                            $resourceDetails = Get-AzResource -ResourceId $resource.Id -ErrorAction SilentlyContinue

                            if ($null -ne $resourceDetails)
                            {
                                if ($resource.Type -eq "Microsoft.ManagedIdentity/userAssignedIdentities")
                                {
                                    # Deleting the role assignements associated with the managed identity before deletion of managed identity.
                                    $roleAssignments = Get-AzRoleAssignment -ObjectId $resourceDetails.Properties.PrincipalId
                                    $roleAssignments | ForEach-Object {
                                        $roleAssignment = $_
                                        $success = Remove-AzRoleAssignment -ObjectId $resourceDetails.Properties.PrincipalId -RoleDefinitionName $roleAssignment.RoleDefinitionName -Scope $roleAssignment.Scope -ErrorAction SilentlyContinue
                                        if(-not $success)
                                        {
                                            $failedRoleAssignments += $roleAssignment
                                        }
                                    }
                                }

                                # Deletion of resource.
                                $success = Remove-AzResource -ResourceType $resource.Type -ResourceGroupName $ResourceGroupName -Name $resource.Name -Force
                                if(-not $success)
                                {
                                    $failedResources += $resource
                                }
                            }
                        }
                        catch
                        {
                            $failedResources += $resource
                        }
                    }

                    if ($($failedResources | Measure-Object).Count -gt 0) {
                        Write-Host "Deletion of the following resource(s) resulted in error:" -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                        $failedResources | Format-Table -Property $colsProperty -Wrap
                        Write-Host "`n`rPlease run the script again to retry deletion on the failed resource(s)." -ForegroundColor $([Constants]::MessageType.Info)
                    }
                    
                    if ($($failedRoleAssignments | Measure-Object).Count -gt 0) {
                        $colsProperty = @{Expression = { $_.RoleDefinitionId }; Label = "RoleDefinitionId"; Width = 30; Alignment = "left" },
                                        @{Expression = { $_.RoleDefinitionName }; Label = "RoleDefinitionName"; Width = 20; Alignment = "left" },
                                        @{Expression = { $_.Scope }; Label = "Scope"; Width = 60; Alignment = "left" }
                            
                        Write-Host "Deletion of the following role assignments(s) resulted in error:" -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                        $failedRoleAssignments | Format-Table -Property $colsProperty -Wrap
                    }

                    if ($($failedResources | Measure-Object).Count -eq 0 -and $($failedRoleAssignments | Measure-Object).Count -eq 0)
                    {
                        Write-Host "AzTS MMA Removal Utility solution resource(s) in the resource group [$($ResourceGroupName)] have been successfully deleted." -ForegroundColor $([Constants]::MessageType.Update)
                    }
                }
                else
                {
                    Write-Host "No resources(s) found in the resource group [$($ResourceGroupName)]. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
            }
        }
        catch
        {
            Write-Host "`n`rError occurred during deletion process. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
    }
}