#***Step 1 - Verify the versions - Windows OS and have PowerShell version 5.0 or higher
$PSVersionTable

# To be in Full Language Mode 
$ExecutionContext.SessionState.LanguageMode

#***Step 2 - Install Az Modules and Azure AD

install-module -name az.accounts -allowclobber -scope currentuser -repository psgallery
install-module -name az.resources -allowclobber -scope currentuser -repository psgallery
install-module -name az.storage -allowclobber -scope currentuser -repository psgallery
install-module -name az.managedserviceidentity -allowclobber -scope currentuser -repository psgallery
install-module -name az.monitor -allowclobber -scope currentuser -repository psgallery
install-module -name az.operationalinsights -allowclobber -scope currentuser -repository psgallery
install-module -name az.applicationinsights -allowclobber -scope currentuser -repository psgallery
install-module -name az.websites -allowclobber -scope currentuser -repository psgallery
install-module -name az.network -allowclobber -scope currentuser -repository psgallery
install-module -name az.frontdoor -allowclobber -scope currentuser -repository psgallery
install-module -name azuread -allowclobber -scope currentuser -repository psgallery


$setupName ='\EntraSetup.ps1'
$path = Read-Host 'Please enter the Complete path where you have kept the setup?'

$completepath = $path + $setupName
Write-Host "Complete path is $completepath"

#*** - Bypassing Execution Policy

Set-ExecutionPolicy Bypass -Scope Process -Force
. $completepath #Load EntraSetup.ps1


Write-Host "Before proceeding with creating the set up, we would like to take few inputs used in this process`n" -ForegroundColor $([Constants]::MessageType.Info) -NoNewline

$TenantId = Read-Host 'Please enter the Host tenant Id?'
Write-Host "You have entered Tenant Id as- $TenantId" -ForegroundColor $([Constants]::MessageType.Info)

$MIHostingSubId = Read-Host 'Please enter the Host Subscription Id?'# Subscription Id in which Set up will be hosted.

Write-Host "You have entered Subscription Id as- $MIHostingSubId" -ForegroundColor $([Constants]::MessageType.Info) 

$AzureEnvironmentName = Read-Host 'Please enter the specific Cloud Type, The Values can be one of "AzureCloud" , "AzureGovernmentCloud", OR "AzureChinaCloud"..'# Subscription Id in which Set up will be hosted.
Write-Host "You have entered AzureEnvironmentName Id as- $AzureEnvironmentName" -ForegroundColor $([Constants]::MessageType.Info)


$Location = Read-Host 'Please enter Your preferred location to keep this set up?'# Subscription Id in which Set up will be hosted.
Write-Host "You have entered location as- $Location" -ForegroundColor $([Constants]::MessageType.Info) 

$HostResourceGroupName = Read-Host 'Please enter Your preferred Resource Group name to keep this set up?'   # Subscription Id in which Set up will be hosted.

$HostResourceGroup= New-AzResourceGroup -Name RgName -Location $Location
Write-Host "Resource Group has been successfully created with name as $HostResourceGroupName and in the location - $Location" -ForegroundColor $([Constants]::MessageType.Update) 


$MIName = "EntraIdScanner-InternalMI"
$ApplicationScannerIdentityName = "Entra-ApplicationScannerIdentity"
$IsSetUpMultiTenant= $true


Write-Host "We will be creating a new RG with name as"  $HostResourceGroupName "`n" -ForegroundColor $([Constants]::MessageType.Update) -NoNewline

Write-Host "We will be creating a new RG with name as"  $SecureResourceGroupName "`n" -ForegroundColor $([Constants]::MessageType.Update) -NoNewline


#***Step 3 - Create Central Scanning Managed Identity 

Disconnect-AzAccount
Disconnect-AzureAD
$TenantId =  $TenantId # Tenant id.
Connect-AzAccount -Tenant $TenantId
Connect-AzureAD -Tenant $TenantId
    
    Write-Host "We will be creating the Multi -Tenant Set up for Entra Id Scanner.`n" -ForegroundColor $([Constants]::MessageType.Update) -NoNewline


    $ApplicationScannerIdenity = CreateAzureADApplication -displayName $ApplicationScannerIdentityName

    Write-Host "Identities got created successfully.`n" -ForegroundColor $([Constants]::MessageType.Update) -NoNewline

    Write-Host "Object Id is:" + $ApplicationScannerIdenity.ObjectId "`n" -ForegroundColor $([Constants]::MessageType.Update) -NoNewline
    Write-Host "App Id is: +" $ApplicationScannerIdenity.AppId "`n" -ForegroundColor $([Constants]::MessageType.Update) -NoNewline     
           
       


$HostSubscriptionId = $MIHostingSubId 
$AzureEnvironmentName = "AzureCloud"
$ScanIdentityHasGraphPermission = $false



$ADApplicationDetails = Set-EntraSecurityADApplication -SubscriptionId $HostSubscriptionId -ScanHostRGName $HostResourceGroupName


#Details of the AD Applications
$ADApplicationDetails.WebAPIAzureADAppId
$ADApplicationDetails.UIAzureADAppId  

Set-AzContext -SubscriptionId  $HostSubscriptionId

$templateName ='\AzTSEntraDeploymentTemplate.json'
$templatefilecompletepath = $path + $templateName
Write-Host "Complete path for deployment template is $templatefilecompletepath"

$DeploymentResult = Install-EntraSecuritySolution `
                -SubscriptionId $HostSubscriptionId `
                -ScanHostRGName $HostResourceGroupName `
                -Location $Location `
                -WebAPIAzureADAppId $ADApplicationDetails.WebAPIAzureADAppId `
                -UIAzureADAppId $ADApplicationDetails.UIAzureADAppId `
                -AzureEnvironmentName $AzureEnvironmentName `
                -ScanIdentityApplicationId $ApplicationScannerIdenity.AppId `
                -TemplateFilePath $templatefilecompletepath `
                -EnableAzTSUI `
                -EnableAutoUpdater `
                -EnableMultiTenantScan  `
                -Verbose
                




$InternalIdentityName = $DeploymentResult.Outputs.internalMIName.Value
$InternalIdentityObjectId = $DeploymentResult.Outputs.internalMIObjectId.Value

# Get the internal Managed Identity details
$mi = Get-AzUserAssignedIdentity -ResourceGroupName $HostResourceGroupName -Name $InternalIdentityName


# Get the host Resource Group details and Assign the Contributor Access on RG.
$resourceGroup = Get-AzResourceGroup -Name $HostResourceGroupName -ErrorAction Stop
$scope = $resourceGroup.ResourceId
$roleDefinitionName = "Contributor"
New-AzRoleAssignment -ObjectId $mi.PrincipalId -RoleDefinitionName $roleDefinitionName -Scope $scope -ErrorAction Stop


Grant-AzSKGraphPermissionToUserAssignedIdentity `
                          -UserAssignedIdentityObjectId  $InternalIdentityObjectId  `
                          -MSGraphPermissionsRequired @('User.Read.All')




