<# *********************************************************************

                         Script execution guidance

   ********************************************************************* #>

   #  To run this script, select a command and press F8.


<# *********************************************************************

                         Installation Prerequisite

   ********************************************************************* #>

# *** 1 of 6. Validate prerequisites on machine
    #Ensure that you are using Windows OS and have PowerShell version 5.0 or higher

    $PSVersionTable

# *** 2 of 6. Installing required Az modules
    # Install required Az modules
    # Required versions: 
    #   Az.Accounts >= 2.9.0
    #   Az.Resources >= 1.10.0
    #   Az.Storage >= 2.0.0
    #   Az.ManagedServiceIdentity >= 0.7.3
    #   Az.Monitor >= 1.5.0
    #   Az.OperationalInsights >= 1.3.4
    #   Az.ApplicationInsights >= 1.0.3
    #   Az.Websites >= 2.8.1
    #   Az.Network  >= 2.5.0
    #   Az.FrontDoor >= 1.8.0
    #	Az.CosmosDB >= 1.8.2
	
    Install-Module -Name Az.Accounts -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.Resources -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.Storage -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.ManagedServiceIdentity -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.Monitor -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.OperationalInsights -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.ApplicationInsights -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.Websites -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.Network -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.FrontDoor -AllowClobber -Scope CurrentUser -repository PSGallery
    Install-Module -Name Az.CosmosDB -AllowClobber -Scope CurrentUser -repository PSGallery

    # Install AzureAd 
    # Required version:
    #   AzureAD >= 2.0.2.130
    Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser -repository PSGallery

# **** 3 of 6. Download and extract deployment template

    # i) If not already done, unblock the content. Below command will help to unblock files.

        # Set extracted folder path
        $DeploymentTemplateFolderPath = "<ExtractedFolderPath>"

        # Unblock files
        Get-ChildItem -Path $DeploymentTemplateFolderPath -Recurse |  Unblock-File 

    # ii) Point current path to deployment folder and load AzTS setup script

        # Point current path to extracted folder location and load setup script from deployment folder 

            CD "$DeploymentTemplateFolderPath"

        # Load AzTS Setup script in session

            . ".\AzTSSetup.ps1"


<# ********************************************************************

         Log in to Azure Portal and Azure Active Directory (AD)

  ********************************************************************* #>

# Tenant id where the AzTS solution needs to be installed.
$TenantId = "<TenantId>"

# Connect to AzureAD and AzAccount with the tenant Id where you want to use AzTS solution.

# NOTE: Tenant Id *must* be specified when connecting to Azure AD and AzAccount.
        
# Clear existing login, if any
# If you are not already connected to Azure, Disconnect command will return an error. In this case, please ignore the error and continue to next step. 
Disconnect-AzAccount
Disconnect-AzureAD

# Connect to AzureAD and AzAccount

Connect-AzAccount -Tenant $TenantId
Connect-AzureAD -TenantId $TenantId


<# ********************************************************************

            Setting up central scan managed identity (scanner MI)

  *********************************************************************

    .Summary

    The AzTS setup provisions your subscriptions with the ability to do daily scans for security controls.
    To do the scanning, it requires a User-assigned Managed Identity (central scanning identity owned by you) which has 'Reader' access 
    on target subscriptions on which scan needs to be performed.

#>

# *** 4 of 6. Setting up scanning identity  

        # ***** Initialize required parameters ******
        
        # Subscription id in which scanner MI needs to be created.
        $MIHostingSubId = "<MIHostingSubId>"
        
        # Resource group name in which scanner MI needs to be created.
        $MIHostingRGName = "<MIHostingRGName>"
        
        # Location in which scanner MI needs to be created.
        $Location = "<Location>"
        
        # Name of the scanner MI.
        $MIName = "<USER ASSIGNED IDENTITY NAME>"
        
        # List of target subscription(s) that needs to be scanned by AzTS.
        # This command assigns 'Reader' access to user-assigned managed identity on target subscriptions. Add target subscription id(s) in place of <SubIdx>
        # Alternatively, you can grant scanner MI 'Reader' access at management group scope instead of individual subscriptions.
        $TargetSubscriptionIds = @("<SubId1>","<SubId2>","<SubId3>")
 

        # i) You can create central scanning user-assigned managed identity (MI) with below PowerShell command 
 
            # Step 1: Create scanner MI and grant 'Reader' permission on target subscriptions.
            $UserAssignedIdentity = Set-AzSKTenantSecuritySolutionScannerIdentity -SubscriptionId $MIHostingSubId `
                                                                                    -ResourceGroupName $MIHostingRGName `
                                                                                    -Location $Location `
                                                                                    -UserAssignedIdentityName $MIName `
                                                                                    -TargetSubscriptionIds $TargetSubscriptionIds
            
            # Step 2: Save resource id and principal Id generated for user identity using below command. This will be used in AzTS Soln installation. 
            
            # Resource id of the user-assigned managed identity
            $UserAssignedIdentity.Id
            
            # Object id of the user-assigned managed identity
            $UserAssignedIdentity.PrincipalId 

        # ii) Grant MS Graph read permission to central scanner MI.
            
            # NOTE: This step requires admin consent. Therefore, the signed-in user must be a member of one of the following administrator roles:
            # Required Permission: Global Administrator or Privileged Role Administrator.
            # If you do not have the permission required to complete this step, please contact your administrator.
            # To proceed without this step, set the value of "-ScanIdentityHasGraphPermission" parameter to false in AzTS installation command (Install-AzSKTenantSecuritySolution) below in 'step 6 of 6'.
            # By setting '-ScanIdentityHasGraphPermission' to $false, you are choosing to disable features dependent on Graph API.

            Grant-AzSKGraphPermissionToUserAssignedIdentity -UserAssignedIdentityObjectId $UserAssignedIdentity.PrincipalId -MSGraphPermissionsRequired @("PrivilegedAccess.Read.AzureResources", "Directory.Read.All") -ADGraphPermissionsRequired @("Directory.Read.All") 

<# ********************************************************************

                    Setup AzTS solution

  ********************************************************************* #>


# ***** Initialize required parameters ******

# Subscription id in which Azure Tenant Security Solution needs to be installed.
$HostSubscriptionId = "<HostSubscriptionId>" 

# Resource group name in which Azure Tenant Security Solution needs to be installed.
$HostResourceGroupName = "<HostResourceGroupName>"

# Location in which resources needs to be created.
# Note: For better performance, we recommend hosting the Central Scanner MI and resources setup using AzTS Soln installation command in one location.
$Location = "<ResourceLocation>"  # e.g. EastUS2

# Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud
$AzureEnvironmentName = "<EnvironmentName>"

# Specify if scanner MI has Graph permission. This is to exclude controls dependent on Graph API reponse from the scan result, if scanner identity does not have graph permission.
$ScanIdentityHasGraphPermission = $false

# The installation creates alert for monitoring health of the AzTS Soln.
# Comma-separated list of user email ids who should be sent the monitoring email.
$SendAlertNotificationToEmailIds =  @('<EmailId1>', '<EmailId2>', '<EmailId3>') 


# *** 5 of 6. Create Azure AD application for secure authentication
        
       
        # Step 1: Setup AD application for AzTS UI and API
        $ADApplicationDetails = Set-AzSKTenantSecurityADApplication -SubscriptionId $HostSubscriptionId -ScanHostRGName $HostResourceGroupName
         
        # Step 2: Save WebAPIAzureADAppId and UIAzureADAppId generated for Azure AD application using below command. This will be used in AzTS Soln installation. 
        
        # Azure AD application client (application) ids
        $ADApplicationDetails.WebAPIAzureADAppId
        $ADApplicationDetails.UIAzureADAppId  

            
# *** 6 of 6. Set context and validate you have 'Owner' access on subscription where solution needs to be installed ****
        
        # Run Setup Command
        # i) Set the context to hosting subscription
        Set-AzContext -SubscriptionId  $HostSubscriptionId

        # ii) Run install solution command 
        # Note : To install AzTS setup with vnet integration, uncomment switch '-EnableVnetIntegration' and then run the installation command
        # Note : To install AzTS setup with WAF enabled, uncomment switch '-EnableWAF' and then run the installation command
        $DeploymentResult = Install-AzSKTenantSecuritySolution `
                        -SubscriptionId $HostSubscriptionId `
                        -ScanHostRGName $HostResourceGroupName `
                        -ScanIdentityId $UserAssignedIdentity.Id `
                        -Location $Location `
                        -WebAPIAzureADAppId $ADApplicationDetails.WebAPIAzureADAppId `
                        -UIAzureADAppId $ADApplicationDetails.UIAzureADAppId `
                        -AzureEnvironmentName $AzureEnvironmentName `
                        -ScanIdentityHasGraphPermission:$ScanIdentityHasGraphPermission `
                        -SendAlertNotificationToEmailIds $SendAlertNotificationToEmailIds `
                        -EnableAutoUpdater `
                        -EnableAzTSUI `
                        -Verbose

        # OTHER SUPPORTED PARAMETERS (read more about its usage in AzTS github doc):
        # 1. -EnableVnetIntegration 
        # 2. -EnableWAF 
        # 3. -CentralStorageAccountConnectionString "<ConnectionString>" 
                        

        # iii) Save internal user-assigned managed identity name generated using below command. This will be used to grant Graph permission to internal MI.
        $InternalIdentityObjectId = $DeploymentResult.Outputs.internalMIObjectId.Value

        # iv) Grant internal MI 'User.Read.All' permission.

        # **Note:** To complete this step, signed-in user must be a member of one of the following administrator roles:
        # Required Permission: Global Administrator or Privileged Role Administrator. 
        # If you do not have the required permission, please contact your administrator.
        # Read more about this under the section "Step 6 of 6. Run Setup Command" in GitHub doc.

        Grant-AzSKGraphPermissionToUserAssignedIdentity `
                          -UserAssignedIdentityObjectId  $InternalIdentityObjectId  `
                          -MSGraphPermissionsRequired @('User.Read.All')


<# ********************************************************************

         Next step: Trigger AzTS Scan using On-Demand scan command

  ********************************************************************* #>

# Note : If your AzTS solution is integrated to vnet, in that case uncomment switch '-EnableVnetIntegration' and then run below command to trigger AzTs scan
Start-AzSKTenantSecuritySolutionOnDemandScan -SubscriptionId $HostSubscriptionId -ScanHostRGName $HostResourceGroupName #-EnableVnetIntegration