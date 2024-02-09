> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

</br>

> We have updated our auto update feature to use AAD Authentication for Function App deployment instead of basic auth or publishing profile. Please refer details [here](../FAQs/README.md/#6-what-are-the-recommended-authentication-settings-for-all-app-services-or-function-apps).

> FAQ for guidance on migrating classic Application Insights to Workspace-based resource [here](../FAQs/README.md/#7-how-can-i-migrate-classic-application-insights-to-workspace-based-resource-if-i-migrate-application-insights-azsk-azts-appinsights-xxxxx-to-workspace-based-resource-will-there-be-any-impact-to-azts-scan).

</br>

# Setting up Azure Tenant Security (AzTS) Solution - Step by Step
 
</br>

## On this page:
  - [Steps to install AzTS Solution](README.md#1-steps-to-install-AzTS-solution)
  - [Manually trigger AzTS on-demand scan for entire tenant](README.md#2-manually-trigger-azts-on-demand-scan-for-entire-tenant)
  - [Verifying that Tenant Security Solution installation is complete](README.md#3-verifying-that-tenant-security-solution-installation-is-complete)
  - [Log Analytics visualization](README.md#4-log-analytics-visualization)
  - [FAQ](README.md#faq)

--------------------------------------------------
</br>

## **1. Steps to install AzTS Solution**

In this section, we will walk through the steps of setting up AzTS Solution. This setup can take up to 30 minutes. There are two methods to setup AzTS solution:

[**Method A:**](README.md#method-a) This method provides granular level details of the different steps involved in setting up AzTS. Setup process is divided into multiple steps and seprate command is provided for each step.

[**Method B:**](README.md#method-b) Provides a quick way to install AzTS solution by wrapping up multiple steps into a single consolidated command. 

## **Method A:**

> _**Note:** You can download the deployment package zip from [here](https://github.com/azsk/AzTS-docs/raw/main/TemplateFiles/DeploymentFiles.zip) and use **ExecutionScript.ps1** present in this package to run the commands mentioned in below steps. Before extracting the zip file, right click on the zip file --> click on 'Properties' --> Under the General tab in the dialog box, select the 'Unblock' checkbox --> Click on 'OK' button._

This setup is divided into six steps:

1. [Validate prerequisites on machine](README.md#step-1-of-6-validate-prerequisites-on-machine)
2. [Installing required Az modules](README.md#step-2-of-6-installing-required-az-modules)
3. [Download and extract deployment package](README.md#step-3-of-6-download-and-extract-deployment-package)
4. [Setup central scanning managed identity](README.md#step-4-of-6-setup-central-scanning-managed-identity)
5. [Create Azure AD application for secure authentication](README.md#step-5-of-6-create-azure-ad-application-for-secure-authentication)
6. [Run Setup Command](README.md#step-6-of-6-run-setup-command)

> _**Note**: You will need help of Azure Active Directory (AD) administrator in step 4, 5 and 6 to grant Microsoft.Graph permission._

Let's start!

### **Step 1 of 6. Validate prerequisites on machine**  

  1. a.  Installation steps are supported using following OS options: 	

      - Windows 10
      - Windows Server 2019
  
  </br>

  1. b. PowerShell 5.0 or higher
      All setup steps will be performed with the help of PowerShell ISE console. If you are unaware of PowerShell ISE, refer [link](PowerShellTips.md) to get a basic understanding.
      Ensure that you are using Windows OS and have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.) 
      If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).    
        ![PowerShell Version](../Images/00_PS_Version.png)  

  </br>

  1. c. PowerShell language mode FullLanguage:  
      To run AzTS setup script, PowerShell language mode for the session must be FullLanguage.
      Ensure that you are using FullLanguage mode by typing **$ExecutionContext.SessionState.LanguageMode** in the PowerShell ISE console window.More details about PowerShell language mode can be found [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?source=recommendations&view=powershell-7.3).
</br>




</br>

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 2 of 6. Installing required Az modules**

Az modules contain cmdlet to deploy Azure resources. These cmdlets are used to create AzTS scan solution resources with the help of ARM template.
Install Az PowerShell Modules using the below command. 
For more details of Az Modules refer [link](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps).

``` PowerShell
# Install required Az modules
# Required versions: 
#   Az.Accounts >= 2.5.1
#   Az.Resources >= 1.10.0
#   Az.Storage >= 2.0.0
#   Az.ManagedServiceIdentity >= 0.7.3
#   Az.Monitor >= 1.5.0
#   Az.OperationalInsights >= 1.3.4
#   Az.ApplicationInsights >= 1.0.3
#   Az.Websites >= 2.8.1
#   Az.Network  >= 2.5.0
#   Az.FrontDoor >= 1.8.0
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

# Install AzureAd 
# Required version:
#   AzureAD >= 2.0.2.130
Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser -repository PSGallery
```

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 3 of 6. Download and extract deployment package**
 
 Deployment package mainly contains:
 1. **ARM templates** which contains resource configuration details that need to be created as part of the setup.
 2.  **Deployment setup scripts** which provides the cmdlet to run installation. <br/>

If you have already downloaded the deployment package zip, directly go to step (3.d).

3.a. Download deployment package zip from [here](https://github.com/azsk/AzTS-docs/raw/main/TemplateFiles/DeploymentFiles.zip) to your local machine. </br>

3.b. Extract zip to local folder location. <br/>

3.c. Unblock the content. The below command will help to unblock files. <br/>

  ``` PowerShell
  Get-ChildItem -Path "<Extracted folder path>" -Recurse |  Unblock-File 
  ```

3.d. Point current path to deployment folder and load AzTS setup script <br/>


  ``` PowerShell
  # Point current path to extracted folder location and load setup script from the deployment folder 

  CD "<LocalExtractedFolderPath>\DeploymentFiles"

  # Load AzTS Setup script in session
  . ".\AzTSSetup.ps1"

  # Note: Make sure you copy  '.' present at the start of the line.

  ```

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 4 of 6. Setup central scanning managed identity**  

The AzTS setup provisions your subscriptions with the ability to do daily scans for security controls.
To do the scanning, it requires a [User-assigned Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) (central scanning identity owned by you) which has 'Reader' access on target subscriptions on which scan needs to be performed.

> _Note:_
> 1. _If subscriptions are organized under [Management Groups](https://docs.microsoft.com/en-us/azure/governance/management-groups/overview) (MG), you can assign reader role for central scanning identity using MG role assignment using [Azure Portal](https://docs.microsoft.com/en-us/azure/security-center/security-center-management-groups#assign-azure-roles-to-other-users). For this you need to be 'Owner' on management group level to perform role assignment._
> 
> 2. _All subscriptions and management groups fold up to the one root management group within the directory. To scan all the subscriptions in your tenant, you can assign reader role at root management group scope. Azure AD Global Administrators are the only users who can grant access at this scope._
> 

</br>

Before creating central scanning user-assigned managed identity, please log in to Azure Portal and Azure Active Directory (AD) where you want to install the AzTS solution using the following PowerShell command.

``` PowerShell
# Clear existing login, if any

Disconnect-AzAccount
Disconnect-AzureAD

# Connect to AzureAD and AzAccount
# Note: Tenant Id *must* be specified when connecting to Azure AD and AzAccount

$TenantId = "<TenantId>"
Connect-AzAccount -Tenant $TenantId
Connect-AzureAD -TenantId $TenantId
```

  **4.a. Create central scanner MI and grant 'Reader' permission on target subscriptions:** You can create a user-assigned managed identity (scanner MI)  for centrally scanning subscriptions in your tenant using the following `Set-AzSKTenantSecuritySolutionScannerIdentity` PowerShell command or Portal steps [here](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-manage-ua-identity-portal). The PowerShell command creates a user-assigned managed identity (scanner MI) and assigns 'Reader' access to this MI on target subscriptions. You need to be 'Owner' on target subscription to perform role assignment.

> **Note:** <br> _As a security best practice, we recommend creating central scanning identity in an isolated subscription with limited permission to secure access to this identity._

``` PowerShell
# -----------------------------------------------------------------#
# Step 1: Create central scanning user-assigned managed identity
# -----------------------------------------------------------------#

$UserAssignedIdentity = Set-AzSKTenantSecuritySolutionScannerIdentity `
                                                -SubscriptionId <MIHostingSubId> `
                                                -ResourceGroupName <MIHostingRGName> `
                                                -Location <Location> `
                                                -UserAssignedIdentityName <MIName> `
                                                -TargetSubscriptionIds @("<SubId1>","<SubId2>","<SubId3>")

# -----------------------------------------------------------------#
# Step 2: Save resource id and principal Id generated for user identity using the below command. This will be used in AzTS Soln installation. 
# -----------------------------------------------------------------#

# Resource id of the user-assigned managed identity
$UserAssignedIdentity.Id

# Object id of the user-assigned managed identity
$UserAssignedIdentity.PrincipalId 

```

**Parameter details:**
|Param Name|Description|Required?
|----|----|----|
| SubscriptionId| Subscription id in which scanner MI needs to be created.| Yes|
|ResourceGroupName| Resource group name in which scanner MI needs to be created.|Yes|
|Location| Location in which scanner MI needs to be created. For better performance, we recommend hosting the MI and resources setup using AzTS Soln installation command in one location.| Yes|
|UserAssignedIdentityName| Name of the scanner MI.| Yes|
|TargetSubscriptionIds| List of target subscription id(s) that needs to be scanned by AzTS. This command assigns 'Reader' access to user-assigned managed identity on target subscriptions.|No|

</br>

**4.b. Grant MS Graph read access:** The scanner MI requires MS Graph permission to read data in your organization's directory, such as users, groups and apps and to validate Role-based access control (RBAC) using Azure AD Privileged Identity Management (PIM). This permission is required for the evaluation of RBAC based controls in AzTS.
</br>

``` PowerShell

# Grant Graph Permission to the user-assigned managed identity.
# Required Permission: Global Administrator or Privileged Role Administrator.

Grant-AzSKGraphPermissionToUserAssignedIdentity `
                            -UserAssignedIdentityObjectId $UserAssignedIdentity.PrincipalId `
                            -MSGraphPermissionsRequired @("PrivilegedAccess.Read.AzureResources", "Directory.Read.All") `
                            -ADGraphPermissionsRequired @("Directory.Read.All") 

```


> **Note:** 
> 1. _This step requires admin consent. Therefore, the signed-in user must be a member of one of the following administrator roles: Global Administrator or Privileged Role Administrator. If you do not have the required permission, please contact your administrator to get "PrivilegedAccess.Read.AzureResources" and "Directory.Read.All" permission for your scanner MI in Azure Active Directory using [this PowerShell script](../Scripts/ScriptToGrantGraphPermissionToScannerMI.ps1?raw=1). To run this script, you need to provide the object id of the user-assigned managed identity (scanner MI) created in **step 4.a**._
> 
> 2. _You can proceed without this step, however, the AzTS Soln will run with limited functionality such as the solution will not be able to scan RBAC controls, classic administrator of a subscription will not be able to use the user interface provided by AzTS Soln (AzTS UI) to request on-demand scan, view control failures etc.,_
>
> </br>

</br>

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 5 of 6. Create Azure AD application for secure authentication**

Tenant reader solution provides a UI-based tool that can be used to perform on-demand scans to verify your fixes sooner, check reasons for control failures and view the latest scan results. This step is required to secure the login and authentication process from UI. Use the `Set-AzSKTenantSecurityADApplication` PowerShell command below to configure the Azure AD applications.

The `Set-AzSKTenantSecurityADApplication` PowerShell command will perform the following operations:

   1. Create Azure AD application for UI, if it does not exist. 
   2. Create Azure AD application for backend API, if it does not exist. 
   3. Update UI AD application redirection URL. 
   4. Grant AD applications permission to request OAuth2.0 implicit flow access tokens. This is required for browser-based apps. 
   5. Grant 'User.Read' permission to UI AD application. This permission is used to read logged in user's details such as name, email, and photo.

> _**Note:** If you do not have the permission to run this command, please contact your administrator to complete the setup using [this PowerShell script](../Scripts/ScriptToSetupAzureADApplicationForAzTSUI.ps1?raw=1). To run this script, you need to provide the subscription id and resource group name in which AzTS solution needs to be installed._

``` PowerShell
# -----------------------------------------------------------------#
# Step 1: Setup AD application for AzTS UI and API
# -----------------------------------------------------------------#

# Add subscription id in which Azure Tenant Security Solution needs to be installed.
$HostSubscriptionId = <HostSubscriptionId>

# Add resource group name in which Azure Tenant Security Solution needs to be installed.
$HostResourceGroupName = <HostResourceGroupName>

# Add Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud, AzureChinaCloud
$AzureEnvironmentName = <AzureEnvironmentName>

$ADApplicationDetails = Set-AzSKTenantSecurityADApplication -SubscriptionId $HostSubscriptionId -ScanHostRGName $HostResourceGroupName -AzureEnvironmentName $AzureEnvironmentName

# -----------------------------------------------------------------#
# Step 2: Save WebAPIAzureADAppId and UIAzureADAppId generated for Azure AD application using the below command. This will be used in AzTS Soln installation. 
# -----------------------------------------------------------------#

# Azure AD application client (application) ids 
$ADApplicationDetails.WebAPIAzureADAppId
$ADApplicationDetails.UIAzureADAppId 

```

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 6 of 6. Run Setup Command** 

This is the last step. You need to run install command present as part setup script with host subscription id (sub where scanning infra resources will get created). 
Setup will create infra resources and schedule daily security control scan on target subscriptions. Please validate you have 'Owner' access on the subscription where the solution needs to be installed.

> **Note:**
> 1. _Setup may take up to 5 minutes to complete._
> 2. _For better performance, we recommend using one location for hosting central scanning user-assigned MI and resources which will be created in the following installation steps using the `Install-AzSKTenantSecuritySolution` cmdlet._
> 3. _To restrict network traffic and to ensure that all inbound communication to critical backend resources of AzTS solution are routed through private network(VNet), install AzTS setup with **VNet integration**. For this you will need to run the installation command `Install-AzSKTenantSecuritySolution` with `-EnableVnetIntegration` switch._
>
>     **Note:** Enabling VNet integration for AzTS setup is not recommended as of now due to [ongoing issue](https://github.com/azsk/AzTS-docs/issues/378) for connectivity to Application Insights over Private link scope
>
> 4. _AzTSDeploymentTemplate provides capability to deploy AzTS UI and API which can be used to see compliance summary against each subscription and scan your subscription(s) manually. To deploy AzTS UI and API run installation command `Install-AzSKTenantSecuritySolution` with `-EnableAzTSUI` switch._
> 5. _If you want to provide additional security to AzTS UI and configure custom rules for accessing public endpoints, you must enable Web Application Firewall (WAF). To know more about WAF visit [here](https://docs.microsoft.com/en-us/azure/web-application-firewall/overview). To enable WAF for AzTS UI and API run the installation command `Install-AzSKTenantSecuritySolution` with `-EnableAzTSUI` and `-EnableWAF` switch._
>
> &nbsp;

6.a. Run installation command with required parameters. 

  ``` PowerShell
# -----------------------------------------------------------------#
# Step 1: Set the context to hosting subscription
# -----------------------------------------------------------------#
Set-AzContext -SubscriptionId <HostSubscriptionId>

# -----------------------------------------------------------------#
# Step 2: Run installation command.
# -----------------------------------------------------------------#

$DeploymentResult = Install-AzSKTenantSecuritySolution `
                -SubscriptionId <HostSubscriptionId> `
                -ScanHostRGName <HostResourceGroupName> `
                -Location <ResourceLocation> `
                -ScanIdentityId <ManagedIdentityResourceId> `
                [-WebAPIAzureADAppId <WebAPIAzureADApplicationId>] `
                [-UIAzureADAppId <UIAzureADApplicationId>] `
                [-AzureEnvironmentName AzureCloud] `
                [-ScanIdentityHasGraphPermission:$true] `
                -SendAlertNotificationToEmailIds @('<EmailId1>', '<EmailId2>', '<EmailId3>') `
                [-EnableAutoUpdater] `
                [-EnableAzTSUI] `
                [-EnableVnetIntegration] `
                [-EnableWAF] `
                -Verbose

  <# Note : Parameters that are provided in square brackets[] in the above installation command are optional parameters. UIAzureADAppId and WebAPIAzureADAppId are mandatory parameters if you are enabling AzTSUI and WAF.
  EnableVnetIntegration and EnableWAF configuration is not recommended together while setting up AzTS.
  #>
  

  # -----------------------------------------------------------------#
  # Step 3: Save internal user-assigned managed identity name generated using the below command. This will be used to grant Graph permission to internal MI.
  # -----------------------------------------------------------------#

# Name of the user-assigned managed identity created for internal operations
  $InternalIdentityObjectId = $DeploymentResult.Outputs.internalMIObjectId.Value
                  
  ```

  Example:
  ```PowerShell
  # Example:

    $DeploymentResult = Install-AzSKTenantSecuritySolution `
                    -SubscriptionId bbbe2e73-fc26-492b-9ef4-adec8560c4fe `
                    -ScanHostRGName AzSK-AzTS-Solution-RG `
                    -ScanIdentityId '/subscriptions/bbbe2e73-fc26-492b-9ef4-adec8560c4fe/resourceGroups/TenantReaderRG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/TenantReaderUserIdentity' `
                    -Location EastUS2 `
                    -EnableAzTSUI `
                    -UIAzureADAppId '000000yy-00yy-00yy-00yy-0000000000yy' `
                    -WebAPIAzureADAppId '000000xx-00xx-00xx-00xx-0000000000xx' `
                    -AzureEnvironmentName AzureCloud `
                    -ScanIdentityHasGraphPermission:$true `
                    -SendAlertNotificationToEmailIds @('User1@Contoso.com', 'User2@Contoso.com', 'User3@Contoso.com') `
                    -EnableAutoUpdater `
                    -Verbose


<#

For '-ScanIdentityId' parameter, 
          (a) use value created for "$UserAssignedIdentity.Id" from prerequisite section step 4.
                              OR
          (b) Run Set-AzSKTenantSecuritySolutionScannerIdentity command provided in step 4.
                              OR
          (c) you can get this resources id by going into Azure Portal --> Subscription where user-assigned MI resource created --> MIHostingRG --> Click on MI resource --> Properties --> Copy ResourceId.

#>

<#
Note: UIAzureADAppId and WebAPIAzureADAppId is mandatory if you are enabling AzTSUI
For '-WebAPIAzureADAppId' and '-UIAzureADAppId' parameter,
          (a) use value created for "$ADApplicationDetails.WebAPIAzureADAppId" and "$ADApplicationDetails.UIAzureADAppId" respectively from step 5.
                                    OR
          (b) Run Set-AzSKTenantSecurityADApplication command provided in step 5.
                                    OR
          (c) you can get this application ids by going into Azure Portal --> Azure Active Directory --> App registrations --> All applications --> Search the application by name --> Click on the AD application --> Overview --> Copy Application (client) ID.

#>
```

**Parameter details:**

|Param Name|Description|Required?
|----|----|----|
|SubscriptionId|Hosting subscription id where Azure Tenant solution will be deployed |TRUE|
|ScanHostRGName| Name of ResourceGroup where setup resources will be created |TRUE|
|ScanIdentityId| Resource id of user managed identity used to scan subscriptions  |TRUE|
|Location|Location where all resources will get created |TRUE|
|WebAPIAzureADAppId| Application (client) id of the Azure AD application to be used by the API. | FALSE |
|UIAzureADAppId | Application (client) id of the Azure AD application to be used by the UI. | FALSE|
|SendAlertNotificationToEmailIds| Send monitoring alerts notification to the specified email ids. | TRUE |
|AzureEnvironmentName| Name of the Azure cloud where Azure Tenant solution will be deployed. The default value is AzureCloud.|FALSE|
|ScanIdentityHasGraphPermission|Switch to enable features dependent on Microsoft Graph API from the scan. Set this to false if user-assigned managed identity does not have Graph permission. The default value is false.|FALSE|
|EnableAutoUpdater | Switch to enable AzTS auto updater. Autoupdater helps to get latest feature released for AzTS components covering updates for security controls. If this is disabled, you can manually update AzTS components by re-running setup command.|FALSE|
|EnableAzTSUI | Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan. |FALSE|
|EnableVnetIntegration | Switch to enable VNet integration for AzTS setup. Enabling VNet integration for AzTS setup, ensures that all critical resources like storage, function apps, log analytics workspace etc that are part of AzTS setup, are not accessible over public internet. </br>**Note:** Enabling VNet integration for AzTS setup is not recommended as of now due to [ongoing issue](https://github.com/azsk/AzTS-docs/issues/378) for connectivity to Application Insights over Private link scope.|FALSE|
|EnableWAF | Switch to enable Web Application Firewall (WAF) for AzTS UI and API. To provide additional security and to protect web applications from common exploits and vulnerabilities, it is recommended to enable WAF. By default [managed rule sets](https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview#azure-managed-rule-sets) are configured and prevention mode is enabled for your WAF policy. You can create [custom rules](https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-create-portal#custom-rules) for your WAF policy as per your requirement. <br> **Note**: EnableVnetIntegration and EnableWAF configuration is not recommended together while setting up AzTS.|FALSE|
|CentralStorageAccountConnectionString|Connection string of the storage account to be used to store the scan logs centrally.|FALSE|
|Verbose| Switch used to output detailed log |FALSE|

</br>

  6.b. **Grant MS Graph read access:** AzTS Soln creates an Internal MI identity used to perform internal operations such as access LA workspace and storage for sending scan results. Internal MI is also used by AzTS UI to read the list of security groups that the user is a member of. For this purpose, internal MI requires 'User.Read.All' permission.
  </br>

  ``` PowerShell
      # Grant 'User.Read.All' permission to internal MI
      Grant-AzSKGraphPermissionToUserAssignedIdentity `
                          -UserAssignedIdentityObjectId  $InternalIdentityObjectId  `
                          -MSGraphPermissionsRequired @('User.Read.All')

  ```

  > **Note:** 
  > 01. _This step requires admin consent. To complete this step, the signed-in user must be a member of one of the following administrator roles: </br> Global Administrator or Privileged Role Administrator.</br>If you do not have the required permission, please contact your administrator to get 'User.Read.All' permission for the internal MI in Azure Active Directory using [this PowerShell script](../Scripts/ScriptToGrantGraphPermissionToInternalMI.ps1?raw=1). To run this script, you need to provide the object id of the user-assigned managed identity (internal MI) created in this step._
  > 
  > 2. _You can proceed without this step. However, please note that if this permission is not granted, users who log in to the AzTS UI will not be able to view subscriptions where they have been granted access to a subscription through a security group._

</br>

  Output looks like below,

  ![Resources](../Images/12_TSS_CommandOutput.png)

> **Note:** 
>
> 1. Tenant Security Solution does not support customization of the App Service name.
>
> 2. By default max timeout limit of function app is set to 9 minutes. This can be modified based on the requirement of your organization. To increase function timeout, you can upgrade to a higher App Service plan and use the `AzureFunctionsJobHost__functionTimeout` app setting in App Service to set the timeout value.
>
> </br>
<br>

**Congratulations! Installation is complete with this step.**
</br>

**Next steps:**

To view scan result in AzTS UI:
1. Copy the AzTS UI link provided at the end of the installation command.
2. We recommend creating a custom domain name for your UI. For steps to create a custom domain, refer to this [link](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain).
3. AzTS UI is \*not\* available for use immediately after installation, as it requires one round of scan to complete to show the scan result in UI. Automated AzTS scans are configured to start at approximately 1:00 AM UTC. Therefore, you can use the [On-Demand scan](README.md#2-manually-trigger-azts-on-demand-scan-for-entire-tenant) command to trigger the scan immediately after installation.
4. Update org-subscription mapping for your subscription(s) in AzTS UI. By default, there is no service mapping for your subscription. Therefore, you see the 'Unknown' value in the Service Filter dropdown in AzTS UI. To add service mapping, follow the steps provided here: 
    - [Step 1: Prepare your org-subscription mapping](/02-Monitoring%20security%20using%20AzTS/README.md#step-1-prepare-your-org-subscription-mapping)
    - [Step 2: Upload your mapping to the Log Analytics (LA) workspace](/02-Monitoring%20security%20using%20AzTS/README.md#step-2-upload-your-mapping-to-the-log-analytics-la-workspace) 


[Manually trigger AzTS on-demand scan for entire tenant](README.md#2-manually-trigger-azts-on-demand-scan-for-entire-tenant)
</br>
[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

## **Method B:**

This setup is divided into three steps:

1. [Validate prerequisites on machine](README.md#step-1-of-3-validate-prerequisites-on-machine)
2. [Download and extract deployment package](README.md#step-2-of-3-download-and-extract-deployment-package)
3. [Run Setup Command](README.md#step-3-of-3-run-consolidated-setup-command)

Let's start!

### **Step 1 of 3. Validate prerequisites on machine**  

  1. a.  Installation steps are supported using following OS options: 	

      - Windows 10
      - Windows Server 2019
  
  </br>

  1. b. PowerShell 5.0 or higher
      All setup steps will be performed with the help of PowerShell ISE console. If you are unaware of PowerShell ISE, refer [link](PowerShellTips.md) to get a basic understanding.
      Ensure that you are using Windows OS and have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.) 
      If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).    
        ![PowerShell Version](../Images/00_PS_Version.png)  

  </br>

  1. c. PowerShell language mode FullLanguage:  
      To run AzTS setup script, PowerShell language mode for the session must be FullLanguage.
      Ensure that you are using FullLanguage mode by typing **$ExecutionContext.SessionState.LanguageMode** in the PowerShell ISE console window.More details about PowerShell language mode can be found [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?source=recommendations&view=powershell-7.3).
</br>

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 2 of 3. Download and extract deployment package**
 
Deployment package mainly contains:<br/>

1- **ARM templates** which contains resource configuration details that need to be created as part of the setup.<br/>
2- **Deployment setup scripts** which provides the cmdlet to run installation. <br/>

If you have already downloaded the deployment package zip, directly go to step (2.d).

2.a. Download deployment package zip from [here](https://github.com/azsk/AzTS-docs/raw/main/TemplateFiles/DeploymentFiles.zip) to your local machine. </br>

2.b. Extract zip to local folder location. <br/>

2.c. Unblock the content. The below command will help to unblock files. <br/>

  ``` PowerShell
  Get-ChildItem -Path "<Extracted folder path>" -Recurse |  Unblock-File 
  ```

2.d. Point current path to deployment folder and load AzTS setup script <br/>


  ``` PowerShell
  # Point current path to extracted folder location and load setup script from the deployment folder 

  CD "<LocalExtractedFolderPath>\DeploymentFiles"

  # Load AzTS Setup script in session
  . ".\AzTSConsolidatedSetup.ps1"

  # Note: Make sure you copy  '.' present at the start of the line.

  ```

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 3 of 3. Run consolidated Setup Command** 

This is the last step. You need to run install command `Install-AzSKTenantSecuritySolutionConsolidated` present as part of setup script with all required parameters (parameters details given below).
This consolidated setup command, will:
1. Check and install missing Az PowerShell modules required to deploy AzTS scan solution resources
2. Setup central scanning identity. For scanning, AzTS requires a [User-assigned Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) (central scanning identity owned by you) which has 'Reader' access on target subscriptions on which scan needs to be performed.
3. Create Azure AD application for secure authentication. This is required to secure the login and authentication process from AzTS UI.
4. Create infra resources and schedule daily security control scan on target subscriptions

> **Note:**
> 1. _Setup may take up to 10 minutes to complete._
> 2. _To restrict network traffic and to ensure that all inbound communication to critical backend resources of AzTS solution are routed through private network(VNet), install AzTS setup with **VNet integration**. For this you will need to run the installation command `Install-AzSKTenantSecuritySolutionConsolidated` with `-EnableVnetIntegration` switch._
> 4. _AzTSDeploymentTemplate provides capability to deploy AzTS UI and API which can be used to see compliance summary against each subscription and scan your subscription(s) manually. To deploy AzTS UI and API run installation command `Install-AzSKTenantSecuritySolutionConsolidated` with `-EnableAzTSUI` switch._
> 5. _If you want to provide additional security to AzTS UI and configure custom rules for accessing public endpoints, you must enable Web Application Firewall (WAF). To know more about WAF visit [here](https://docs.microsoft.com/en-us/azure/web-application-firewall/overview). To enable WAF for AzTS UI and API run the installation command `Install-AzSKTenantSecuritySolutionConsolidated` with `-EnableAzTSUI` and `-EnableWAF` switch._
> 6. _As a security best practice, we recommend creating central scanning identity in an isolated subscription with limited permission to secure access to this identity._
> 7. _Scanner identity (MI) requires MS Graph permission to read data in your organization's directory, such as users, groups and apps and to validate Role-based access control (RBAC) using Azure AD Privileged Identity Management (PIM). To grant this permission as part of setup flow, please specify `-GrantGraphPermissionToScanIdentity` switch in installation command. This requires admin consent. Therefore, the signed-in user must be a member of one of the following administrator roles: </br>Global Administrator or Privileged Role Administrator.</br>If you do not have the required permission, please contact your administrator to get "PrivilegedAccess.Read.AzureResources" and "Directory.Read.All" permission for your scanner MI in Azure Active Directory using [this PowerShell script](../Scripts/ScriptToGrantGraphPermissionToScannerMI.ps1?raw=1). To run this script, you need to provide the object id of the user-assigned managed identity (scanner MI) which will be available in deployment log file._
> 8. _AzTS Soln creates an Internal MI identity used to perform internal operations such as pushing scan results to different storages (like Log Analytics workspace and Storage account). Internal MI is also used by AzTS UI to read the list of security groups that the user is a member of. For this purpose, internal MI requires 'User.Read.All' permission. To grant this permission as part of setup flow, please specify `-GrantGraphPermissionToInternalIdentity` switch in installation command. This requires admin consent. Therefore, the signed-in user must be a member of one of the following administrator roles: </br>Global Administrator or Privileged Role Administrator.</br>If you do not have the required permission, please contact your administrator to get 'User.Read.All' permission for the internal MI in Azure Active Directory using [this PowerShell script](../Scripts/ScriptToGrantGraphPermissionToInternalMI.ps1?raw=1). To run this script, you need to provide the object id of the user-assigned managed identity (internal MI) which will available in deployment logs file._
>
> &nbsp;

3. Run consolidated installation command with required parameters. 

  ``` PowerShell
# -----------------------------------------------------------------#
# Step 1: Login to Azure and Azure Active Directory (AAD)
# -----------------------------------------------------------------#

# Clear existing login, if any
Disconnect-AzAccount
Disconnect-AzureAD

# Connect to AzureAD and AzAccount
# Note: Tenant Id *must* be specified when connecting to Azure AD and AzAccount
$TenantId = "<TenantId>"
Connect-AzAccount -Tenant $TenantId
Connect-AzureAD -TenantId $TenantId

# -----------------------------------------------------------------#
# Step 2: Run installation command.
# -----------------------------------------------------------------#

$DeploymentResult = Install-AzSKTenantSecuritySolutionConsolidated `
                    -ScanningIdentityHostSubId <HostSubscriptionIdForScanningIdentity>`
                    -ScanningIdentityHostRGName  'HostRGNameForScanningIdentity' `
                    -ScanningIdentityName 'ScanningIdentityName' `
                    -SubscriptionId 'HostSubscriptionIdForScanningInfra'`
                    -ScanHostRGName 'HostRGForScanningInfra'`
                    -Location 'ResourceLocation'`
                    -SubscriptionsToScan @("<SubId1>","<SubId2>","<SubId3>") `
                    -SREEmailIds @('<EmailId1>', '<EmailId2>', '<EmailId3>') ` #Email Ids of Site Reliability Engineers or Users who should receive monitoring alerts
                    [-GrantGraphPermissionToScanIdentity:$true] `
                    [-GrantGraphPermissionToInternalIdentity:$true] `
                    [-SetupAzModules] `
                    [-AzureEnvironmentName AzureCloud] `
                    [-EnableAutoUpdates] `
                    [-EnableAzTSUI] `
                    [-EnableVnetIntegration] `
                    [-EnableWAF] `
                    -Verbose

  <# Note : 1) Parameters that are provided in square brackets[] in the above installation command are optional.
  2) EnableVnetIntegration and EnableWAF configuration is not recommended together while setting up AzTS. 
  #>
  ```

  Example:
  ```PowerShell
  # Example:

    $DeploymentResult = Install-AzSKTenantSecuritySolutionConsolidated `
                    -ScanningIdentityHostSubId bbbe2e73-fc26-492b-9ef4-adec8560c4fe `
                    -ScanningIdentityHostRGName AzTS-ScanIdentity-RG `
                    -ScanningIdentityName 'AzTSScanManagedIdentity' `
                    -SubscriptionId 26860b59-b5fb-4bb2-8478-a2bd393a0e5b `
                    -ScanHostRGName AzTS-Solution-RG `
                    -Location EastUS2 `
                    -EnableAzTSUI `
                    -AzureEnvironmentName AzureCloud `
                    -SubscriptionsToScan @("43143eaf-1942-4780-8c4a-fefb12d8b2e1","26860b59-b5fb-4bb2-8478-a2bd393a0e5b","bbbe2e73-fc26-492b-9ef4-adec8560c4fe") `
                    -GrantGraphPermissionToScanIdentity:$true `
                    -GrantGraphPermissionToInternalIdentity:$true `
                    -SREEmailIds @('User1@Contoso.com', 'User2@Contoso.com', 'User3@Contoso.com') `
                    -EnableAutoUpdates `
                    -Verbose

```
**Parameter details:**

|Param Name|Description|Required?
|----|----|----|
|ScanningIdentityHostSubId| Subscription id in which scanner identity (MI) is to be created. |TRUE|
|ScanningIdentityHostRGName| Name of ResourceGroup where scanner identity (MI) will be created. |TRUE|
|ScanningIdentityName| Name of the scanning identity (MI) to be created/used by the scanner.  |TRUE|
|SubscriptionId| Hosting Subscription id in which Azure Tenant Security Solution needs to be installed. |TRUE|
|ScanHostRGName| Name of ResourceGroup where setup resources will be created. |TRUE|
|Location| Location where all resources will get created. |TRUE|
|SREEmailIds| Email Ids of Site Reliability Engineers or Users to which alert notification should be sent. | TRUE |
|AzureEnvironmentName| Name of the Azure cloud where Azure Tenant solution will be deployed. The default value is AzureCloud.|FALSE|
|SubscriptionsToScan| List of subscription(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target subscription. So, you need to be 'Owner' on all target subscriptions to perform role assignment.|TRUE|
|ManagementGroupsToScan| List of target management group(s) to be scanned by Azure Tenant Security scanning solution. Scanning identity will be granted 'Reader' access on target management group. For this you need to be 'Owner' on management group level to perform role assignment. </br> To scan all the subscriptions in your tenant, you can provide root management group as input. But Azure AD Global Administrators role will be required to grant required RBAC role to scanning identity at this scope.|FALSE|
|GrantGraphPermissionToScanIdentity| Switch to grant Graph permission to scanning identity. This is to exclude controls dependent on Graph API response from the scan result, if scanner identity does not have graph permission. The default value is false.|FALSE|
|GrantGraphPermissionToInternalIdentity| Switch to grant Graph permissions to internal managed identity. The default value is false.|FALSE|
|ScanIdentityHasGraphPermission|Switch to enable features dependent on Microsoft Graph API from the scan. Set this to false if user-assigned managed identity (in case using existing managed identity) does not have Graph permission. The default value is false.|FALSE|
|EnableAutoUpdates | Switch to enable AzTS auto updater. Autoupdater helps to get latest feature released for AzTS components covering updates for security controls. If this is disabled, you can manually update AzTS components by re-running setup command.|FALSE|
|EnableAzTSUI | Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan. |FALSE|
|EnableVnetIntegration | Switch to enable VNet integration for AzTS setup. Enabling VNet integration for AzTS setup, ensures that all critical resources like storage, function apps, log analytics workspace etc that are part of AzTS setup, are not accessible over public internet. </br>**Note:** Enabling VNet integration for AzTS setup is not recommended as of now due to [ongoing issue](https://github.com/azsk/AzTS-docs/issues/378) for connectivity to Application Insights over Private link scope. |FALSE|
|EnableWAF | Switch to enable Web Application Firewall (WAF) for AzTS UI and API. To provide additional security and to protect web applications from common exploits and vulnerabilities, it is recommended to enable WAF. By default [managed rule sets](https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview#azure-managed-rule-sets) are configured and prevention mode is enabled for your WAF policy. You can create [custom rules](https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-create-portal#custom-rules) for your WAF policy as per your requirement.<br> **Note**: EnableVnetIntegration and EnableWAF configuration is not recommended together while setting up AzTS. |FALSE|
|StorageAccountConnectionString|Connection string of the storage account to be used to store the scan logs centrally.|FALSE|
|SetupAzModules| Switch to validate required modules, command will check needed modules with required version and will install required modules if not available in the system |FALSE|
|Verbose| Switch used to output detailed log |FALSE|

</br>

> **Note:** 
>
> 1. Tenant Security Solution does not support customization of the App Service name.
>
> 2. By default max timeout limit of function app is set to 9 minutes. This can be modified based on the requirement of your organization. To increase function timeout, you can upgrade to a higher App Service plan and use the `AzureFunctionsJobHost__functionTimeout` app setting in App Service to set the timeout value.
>
> 
</br>
<br>

**Congratulations! Installation is complete with this step.**
</br>

**Next steps:**

To view scan result in AzTS UI:
1. Copy the AzTS UI link provided at the end of the installation command.
2. We recommend creating a custom domain name for your UI. For steps to create a custom domain, refer to this [link](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain).
3. AzTS UI is \*not\* available for use immediately after installation, as it requires one round of scan to complete to show the scan result in UI. Automated AzTS scans are configured to start at approximately 1:00 AM UTC. Therefore, you can use the [On-Demand scan](README.md#2-manually-trigger-azts-on-demand-scan-for-entire-tenant) command to trigger the scan immediately after installation.
4. Update org-subscription mapping for your subscription(s) in AzTS UI. By default, there is no service mapping for your subscription. Therefore, you see the 'Unknown' value in the Service Filter dropdown in AzTS UI. To add service mapping, follow the steps provided here: 
    - [Step 1: Prepare your org-subscription mapping](/02-Monitoring%20security%20using%20AzTS/README.md#step-1-prepare-your-org-subscription-mapping)
    - [Step 2: Upload your mapping to the Log Analytics (LA) workspace](/02-Monitoring%20security%20using%20AzTS/README.md#step-2-upload-your-mapping-to-the-log-analytics-la-workspace) 


[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

## **2. Manually trigger AzTS on-demand scan for entire tenant**

> **Note:** 
> _AzTS has been designed to auto-trigger the scan once every 24 hours._ 

The following section will walk you through the steps to trigger AzTS scan manually post-installation.

### **Prerequisite**

1. [Validate prerequisites on machine](README.md#step-1-of-6-validate-prerequisites-on-machine)
2. [Installing required Az modules](README.md#step-2-of-6-installing-required-az-modules)
3. [Download and extract deployment package](README.md#step-3-of-6-download-and-extract-deployment-package)

### **Trigger on-demand scan**

Run the `Start-AzSKTenantSecuritySolutionOnDemandScan` command to start scan after the installation of AzTS Soln. Please note that after running this command, AzTS UI will available in the next 2 hours depending on the number of subscriptions to be scanned.

> **Note:** 
> _If your AzTS solution is integrated to VNet, in that case, to trigger AzTS scan, run `Start-AzSKTenantSecuritySolutionOnDemandScan` command with `-EnableVnetIntegration` switch._


```PowerShell
# Subscription id in which Azure Tenant Security Solution has been installed.
$HostSubscriptionId = "<HostSubscriptionId>"

# Name of ResourceGroup in which Azure Tenant Security Solution has been installed.
$HostResourceGroupName = "<HostResourceGroupName>"

Start-AzSKTenantSecuritySolutionOnDemandScan -SubscriptionId $HostSubscriptionId `
                                             -ScanHostRGName $HostResourceGroupName `
                                             [-EnableVnetIntegration]

```

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

## **3. Verifying that Tenant Security Solution installation is complete**

The below steps will help you to verify and understand different resources and functions created as part of the setup along with purpose. This step can take up to 30 minutes. 

#### **Step 1 of 3: Verify resources created as part of setup**

**1.a.** In the Azure portal, Go to hosting subscription, select the scan host resource group that has been created during the setup.

**1.b.** Verify below resources got created.

  ![Resources](../Images/12_TSS_Resource_Group_1.png)	
  ![Resources](../Images/12_TSS_Resource_Group_2.png)	

  > **Note:** _If WAF is enabled for AzTS Solution, verify that below additional resources also got created, along with the once shown above._

  ![Resources](../Images/12_TSS_Resource_Group_6.png)	

  > **Note:** _If the AzTS Solution is integrated to VNet, verify that below additional resources also got created, along with the once shown above._

  ![Resources](../Images/12_TSS_Resource_Group_3.png)	
  ![Resources](../Images/12_TSS_Resource_Group_4.png)
  ![Resources](../Images/12_TSS_Resource_Group_4.png)	  

**Resources details:**

|Resource Name|Resource Type|Description|
|----|----|----|
|AzSK-AzTS-MetadataAggregator-xxxxx|Function App| Contains functions to get inventory (subscription, baseline controls and RBAC) and queue subscription for scan |
|AzSK-AzTS-WorkItemProcessor-xxxxx|Function App | Contains function to scan subscription with baseline control |
|AzSK-AzTS-WebApi-xxxxx|App Service| Contains API consumed by the AzTS user interface |
|AzSK-AzTS-UI-xxxxx|App Service| Contains AzTS user interface which can be used to view the scan result |
|AzSK-AzTS-UI-xxxxx/Staging-xxxxx| App service slot| Staging slot created to prevent UI downtime during auto-update|
|AzSK-AzTS-AutoUpdater-xxxxx|Function App | Contains function to scan automatically updater function apps and web service apps |
|AzSK-AzTS-LAWorkspace-xxxxx|Log Analytics workspace| Used to store scan events, inventory, subscription scan progress details|
|AzSK-AzTS-InternalMI|Managed Identity | Internal MI identity used to access LA workspace and storage for sending scan results|
|AzSK-AzTS-AppServicePlan | Web App Service Plan| Web app service plan|
|AzSK-AzTS-API-AppServicePlan | Function App Service Plan| Function app service plan|
|AzSK-AzTS-AutoUpdater-LogicApp-xxxxx| Logic App| Logic App required to upgrade the auto-updater service |
|azsktsstoragexxxxx|Storage Account| Used to store the daily results of subscriptions scan|
|AzSK-AzTS-AppInsights |App Insight| Used to collect telemetry logs from functions |
|AzSK-AzTS-Vnet-xxxxx|Virtual Network| Virtual Network to enable secure communication of Azure resources with each other, it also ensures that all inbound communication to the resources gets routed through virtual network |
|AzSK-AzTS-private-link-scope-xxxxx|Azure Monitor Private Link Scope| Used to connect private endpoints to Azure Monitor resources - Log Analytics workspaces and Application Insights, thereby ensuring that monitoring data is only accessed through authorized private networks |
|AzSK-AzTS-private-link-scope-xxxxx-private-endpoint |Private Endpoint| Enables secure connectivity between the consumers from the same VNet, it is used to connect Azure Monitor Private Link Scope to the VNet|
|privatelink-ods-opinsights-azure-com|Private DNS Zone| This zone covers workspace-specific mapping to ODS endpoints - the ingestion endpoint of Log Analytics|
|privatelink-oms-opinsights-azure-com|Private DNS Zone| This zone covers workspace-specific mapping to OMS endpoints|
|privatelink-monitor-azure-com|Private DNS Zone| This zone covers the global endpoints used by Azure Monitor|
|privatelink-agentsvc-azure-automation-net|Private DNS Zone| This zone covers workspace-specific mapping to the agent service automation endpoints|
|privatelink-agentsvc-azure-automation-net|Private DNS Zone| This zone configures connectivity to the global agents' solution packs storage account|
|AzSK-AzTS-API-FrontDoor-xxxxx|Front Door| Used to stop network and application layer attacks at the edge with the help of Web Application Firewall. It secures your private back ends(API) and harden your service using Microsoft managed rule sets|
|AzSK-AzTS-UI-FrontDoor-xxxxx|Front Door| Used to stop network and application layer attacks at the edge with the help of Web Application Firewall. It secures your private back ends(UI) and harden your service using Microsoft managed rule sets|
|AzSKAzTSWAFPolicyxxxxx|Front Door WAF policy| WAF policy with managed Default Rule Set that protect your web application from common threats|

<br/>

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

<br/>

#### **Step 2 of 3: Verify below Functions got created**

 **2.a. MetadataAggregator Functions:** 

&nbsp;&nbsp;&nbsp;Metadata aggregator function performs two tasks: 
1. Collects inventory required for scanning (Target subscription list to be scanned, baseline controls list and subscription RBAC details)
2. Queue subscriptions for scanning
<br/>

&nbsp;&nbsp;&nbsp;Click on 'AzSK-AzTS-MetadataAggregator-xxxxx' function app present in scan hosting RG --> Click on 'Functions' tab in left menu

&nbsp;&nbsp;&nbsp;&nbsp;![ProcessorWebjobs](../Images/12_TSS_Processor_WebJobs_1.png)

|Function Name|Description|
|----|----|
|ATS_01_SubscriptionInvProcessor| Responsible to fetch details about all the subscriptions that have been granted access as Reader using central MI. All these subscriptions will be fetched by the job and persisted into LA. These subscriptions are scanned automatically by consecutive jobs.
|ATS_02_BaselineControlsInvProcessor| Responsible to push baseline controls metadata to LA and storage account
|ATS_03_SubscriptionRBACProcessor| Collects RBAC details of subscription to be scanned. RBAC collected is used to scan the control like "Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities" 
|ATS_04_WorkItemScheduler|  Responsible to queue up subscriptions as workitems for scanning. It also reconciles the errored subscriptions through retries in the end. By default, it would retry to scan 5 times for each error subscription. If there is nothing to process for the day, it would simply ignore the run.
|ATS_05_MGTreeProcessor| Responsible to fetch details about all the management group that has been granted access as Reader using central MI. All these management groups will be fetched by the job and persisted into LA. This function is disabled by default. To enable this function, you need to add/update ` FeatureManagement__ManagementGroups : true ` and `ManagementGroupConfigurations__ManagementGroupId : <Root_Management_Group_id> ` application setting on Azure Portal. To update settings, go to your App Service --> Configuration --> New application settings --> Save after adding/updating the setting.
|ATS_07_InitiateOnDemandProcessing| Responsible to queue MetadataAggregator's functions (ATS_01_SubscriptionInvProcessor, ATS_02_BaselineControlsInvProcessor, ATS_03_SubscriptionRBACProcessor, ATS_04_WorkItemScheduler) for processing. **Note**: This function will only be available if premium tier pricing plan is used for the function app. Also this function is available by default for AzTS solution with VNet integration, as the pricing plan used here is premium tier.
|ATS_08_SecureScoreProcessor| Responsible to fetch details of Secure Score provided by Microsoft Defender for Cloud. This data will be persisted into Log Analytics.
|ATS_09_PolicyStateProcessor| Responsible to collect policy state data (compliance details of policy assignments), collected data is used to evaluate Azure policy based controls. This function is disabled by default and will be enabled as part of [prerequisites](../06-Customizing%20AzTS%20for%20your%20org/Extending%20AzTS/AddControlForPolicy.md) to add custom Azure policy based controls.
|ATS_10_ARGInvProcessor| Responsible to collect dynamic data from Azure Resource Graph based on configured queries.

 **2.b. WorkItemProcessor Functions:** 
 
 Read subscription list from queue and scan for baseline controls.

![SchedulerWebjobs](../Images/12_TSS_Scheduler_Webjobs.png)


> **Note:** Functions are scheduled to run from UTC 00:00 time. You can also run the functions manually in sequence with an interval of 10 mins in each function trigger

Steps to trigger the functions

Click on 'AzSK-AzTS-MetadataAggregator-xxxxx' function app present in scan hosting RG --> Click on 'Functions' tab --> Select 'ATS_01_SubscriptionInvProcessor' --> Click on 'Code + Test' --> Click 'Test/Run' --> Click 'Run'

Similarly, you can trigger below functions with 10 mins interval.

 * ATS_02_BaselineControlsInvProcessor

 * ATS_03_SubscriptionRBACProcessor 
 
 * ATS_04_WorkItemScheduler 

After ATS_04_WorkItemScheduler completes pushing the messages in the queue, WorkItemProcessor will get auto trigged, start processing scan and push scan results in Storage Account and LA workspace. 

> **Note:** If AzTS solution is integrated to VNet, you cannot run the functions manually. To trigger all the required functions run [On-Demand scan](README.md#2-manually-trigger-azts-on-demand-scan-for-entire-tenant) command with `-EnableVnetIntegration` switch.

 **2.c. AutoUpdater Functions:** 
 
 Timer-based function app to automatically update other function apps (Metadataaggregator and WorkItemProcessor) and Azure web service app(UI and API). User has the option to configure AutoUpdater settings like isAutoUpdateOn (user wants to auto-update with new releases), VersionType (user wants to install the latest release/stable release/specific version).
 
 AutoUpdater is a cron job which runs twice a day at 02:00 PM and 04:00 PM (UTC) to check for new release to update the apps. You can also manually trigger the AutoUpdater function if needed.
 Our AutoUpdater is robust enough to handle different configuration for each function app or web service app.

> **Note:** If you want to install a specific version for each different apps (or a specific version for all) follow the below steps,
>
> (i) Change the VersionType from **"stable/latest"** to the required version number eg., **"x.y.z"** in Auto Updater App services app setting. To update the version, go to AzSK-AzTS-AutoUpdater-xxxxx app service --> Configuration --> Add app setting `HostEnvironmentDetails__AutoUpdateConfig__<Id>__VersionType` and set value to the required version,
> </br>
>
> |App Service| Id| Example of app setting name |
> |--|--|--|
> |AzSK-AzTS-MetadataAggregator-xxxxx | 0 |HostEnvironmentDetails__AutoUpdateConfig__0__VersionType|
> |AzSK-AzTS-WorkItemProcessor-xxxxx | 1 |HostEnvironmentDetails__AutoUpdateConfig__1__VersionType|
> |AzSK-AzTS-WebApi-xxxxx | 2 |HostEnvironmentDetails__AutoUpdateConfig__2__VersionType|
> |AzSK-AzTS-UI-xxxxx | 3 |HostEnvironmentDetails__AutoUpdateConfig__3__VersionType|
>
> </br>
>
> (ii) Manually trigger the AutoUpdate function app. You can view the console/monitor logs to see the appropriate status of the AutoUpdater function.
> </br>
>
> (iii) After AutoUpdater function execution gets complete, you need to change **isAutoUpdateOn** (`HostEnvironmentDetails__AutoUpdateConfig__<id>__IsAutoUpdateOn`) to **false** through the app configuration setting for the apps where you want to keep custom version installed.

<br/>

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

#### **Steps 3 of 3: Verify AzTS UI is working as expected**

**Prerequisite:**

1. Signed in user must have one of the following permissions at subscription or resource group scope: Owner, Contributor, ServiceAdministrator, CoAdministrator, AccountAdministrator, Security Reader, Security Admin.

2. Subscription scan should have completed for the day. Automated AzTS scans are configured to start at approximately 1:00 AM UTC. You can use the [On-Demand scan](README.md#2-manually-trigger-azts-on-demand-scan-for-entire-tenant) command to trigger the scan immediately after the installation.

**Steps to load AzTS UI:**

  **3.a.** Use the URL provided at the end of  ```Install-AzSKTenantSecuritySolution``` installation command (as shown below). If required, you can run the installation command again to get this URL.

&nbsp;&nbsp;![UI](../Images/13_TSS_UIUrlPrintMessageInPSOutput.png) 

**3.b.** Open the URL is browser.

> _**Note:** We recommend creating a custom domain name for your UI. For steps to create a custom domain, refer to this [link](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain)._

&nbsp;&nbsp;<img src="../Images/13_TSS_UIOverview.png" width="80%">

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

> **Note:** We recommend reviewing role assignemnts periodically for critical resources like:
1. Subscriptions and resource groups containing managed identity and other AzTS resources.
2. Storage account in AzTS host resource group (as this contains scan results data)
3. Log Analytics workspace in AzTS host resource group (as this contains scan results data)

  Also, as a good security practice, consider rotating keys for Storage account and  Log Analytics workspacere periodically. Once Log Analytics workspace key is rotated, Power BI dashboards used for monitoring would need updating and re-publishing.

## **4. Log Analytics Visualization**

For understanding the collected data, use the querying and visualization capabilities provided by Log Analytics. 
To start, go to **Log Analytics workspace** created during setup --> Select **Logs**. 


Few more simple queries to try

#### A. Inventory summary

##### Subscription Inventory 

``` KQL

AzSK_SubInventory_CL
| where TimeGenerated > ago(1d)
| where JobId_d ==  toint(format_datetime(now(), 'yyyyMMdd'))
| where State_s != 'Disabled'
| summarize arg_max(TimeGenerated, *) by SubscriptionId
| distinct SubscriptionId, Name_s

```

##### Baseline control list supported by AzTS Scan

``` KQL
AzSK_BaselineControlsInv_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by ControlId_s
| project ControlId_s, ResourceType, Description_s, ControlSeverity_s, Tags_s
```

#### Role-based access control (RBAC) summary

``` KQL
AzSK_RBAC_CL
| where TimeGenerated > ago(1d) and JobId_d == toint(format_datetime(now(), 'yyyyMMdd')) 
| summarize arg_max(TimeGenerated, *) by RoleId_g, RoleId_s
| project ObjectId = UserName_g, AccountType_s,RoleName_s, IsPIMEligible_b, Scope_s
```

#### Subscription scanned today

``` KQL
AzSK_ProcessedSubscriptions_CL
|  where TimeGenerated > ago(1d) and JobId_d == toint(format_datetime(now(), 'yyyyMMdd')) and EventType_s =~"Completed"
| summarize arg_max(TimeGenerated,*) by SubscriptionId
| project ScanTimeInUTC = TimeGenerated, SubscriptionId 
```

#### B. Control Scan Summary


##### Top 20 failing controls

``` KQL

AzSK_ControlResults_CL
| where TimeGenerated > ago(2d) 
| where JobId_d == toint(format_datetime(now(), 'yyyyMMdd'))
| summarize arg_max(TimeGenerated, *) by SubId = tolower(SubscriptionId), RId= tolower(ResourceId), ControlName_s
| summarize TotalControls = count(), FailedControl = countif(VerificationResult_s =~ "Failed") by ControlName_s
| order by FailedControl desc 
| take 20

```

##### Top 10 subscription with most failing controls

``` KQL
AzSK_ControlResults_CL
| where TimeGenerated > ago(1d)
| where JobId_d == toint(format_datetime(now(), 'yyyyMMdd'))
| summarize arg_max(TimeGenerated, *) by SubscriptionId = tolower(SubscriptionId), ResourceId= tolower(ResourceId), ControlName_s
| where VerificationResult_s =~ "Failed"
| summarize FailedCount = count() by SubscriptionId
| order by FailedCount desc 
| take 10
```

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

## FAQ
Please find FAQs [here](../FAQs/README.md)

