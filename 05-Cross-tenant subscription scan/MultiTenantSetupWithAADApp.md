> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

</br>

# Setting up multi-tenant Azure Tenant Security (AzTS) Solution - Step by Step
 
</br>

## On this page:
  - [Steps to install multi tenant AzTS Solution](MultiTenantSetupWithAADApp.md#1-steps-to-install-multi-tenant-azts-solution)
  - [Onboard tenants for scanning](MultiTenantSetupWithAADApp.md#2-onboard-tenants-for-scanning)
  - [FAQs](MultiTenantSetupWithAADApp.md#3-faqs)

--------------------------------------------------
</br>

## **1. Steps to install multi-tenant AzTS Solution**

In this section, we will walk through the steps for setting up multi-tenant AzTS Solution with central AAD App based scanning model. This setup may take up to 30 minutes.

This setup is divided into following seven steps:

1. [Validate prerequisites on machine](MultiTenantSetupWithAADApp.md#step-1-of-7-validate-prerequisites-on-machine)
2. [Installing required Az modules](MultiTenantSetupWithAADApp.md#step-2-of-7-installing-required-az-modules)
3. [Download and extract deployment package](MultiTenantSetupWithAADApp.md#step-3-of-7-download-and-extract-deployment-package)
4. [Setup central scanning identity](MultiTenantSetupWithAADApp.md#step-4-of-7-setup-central-scanning-identity)
5. [Create Azure AD application for secure authentication](MultiTenantSetupWithAADApp.md#step-5-of-7-create-azure-ad-application-for-secure-authentication)
6. [Run Setup Command](MultiTenantSetupWithAADApp.md#step-6-of-7-run-setup-command)
7. [Grant required permission to internal MI](MultiTenantSetupWithAADApp.md#step-7-of-7-grant-required-permission-to-internal-mi)

Let's start!

### **Step 1 of 7. Validate prerequisites on machine**  

  1. a.  Installation steps are supported using following OS options: 	

      - Windows 10
      - Windows Server 2019
  
  </br>

  1. b. PowerShell 5.0 or higher
  All setup steps will be performed with the help of PowerShell ISE console. If you are unaware of PowerShell ISE, refer [link](../01-Setup%20and%20getting%20started/PowerShellTips.md) to get a basic understanding.
  Ensure that you are using Windows OS and have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.) 
  If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).  

      ![PowerShell Version](../Images/00_PS_Version.png)

</br>

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)

### **Step 2 of 7. Installing required Az modules**

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
#   Az.KeyVault  >= 1.5.0
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
Install-Module -Name Az.KeyVault -AllowClobber -Scope CurrentUser -repository PSGallery


# Install AzureAd 
# Required version:
#   AzureAD >= 2.0.2.130
Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser -repository PSGallery
```

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)

### **Step 3 of 7. Download and extract deployment package**
 
 Deployment package mainly contains:
 1. **ARM templates** which contains resource configuration details that need to be created as part of the setup.
 2.  **Deployment setup scripts** which provides the cmdlet to run installation. <br/>

If you have already downloaded the deployment package zip, directly go to step (3.d).

3.a. Download deployment package zip from [here](../TemplateFiles/DeploymentFiles.zip?raw=1) to your local machine. </br>

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

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)

### **Step 4 of 7. Setup central scanning identity**  

The AzTS setup performs daily scans of your subscriptions for security controls. To do the scanning, it requires a central multi-tenant AAD (Azure Active Directory) application in Host tenant. Later SPN (Service principal) of the same applicaton needs to be created in each target tenant and will have 'Reader' access on subscriptions in each target tenant.

Before creating central multi-tenant AAD app, please log in to Azure account and Azure Active Directory (AAD) where you want to host the AzTS solution using the following PowerShell command.

``` PowerShell
# Clear existing login, if any

Disconnect-AzAccount
Disconnect-AzureAD

# Connect to AzureAD and AzAccount
# Note: Host Tenant Id (Tenant in which AzTS solution needs to be installed) *must* be specified when connecting to Azure AD and AzAccount

$TenantId = "<TenantId>"
Connect-AzAccount -Tenant $TenantId
Connect-AzureAD -TenantId $TenantId
```

 **4.a. Create central multi-tenant AAD application for scanning:** 
 The PowerShell command creates a multi-tenant AAD application and new secret (with 6 months expiry). You should have permission to create new multi-tenant AAD application in host tenant. 


> **Note:** <br> _As a security best practice, please do not put secret in any local file or any other place exept Key Vault._

``` PowerShell
# -----------------------------------------------------------------#
# Step 1: Create central scanning identity (multi-tenant AAD Application)
# -----------------------------------------------------------------#

$appDetails = Create-AzSKTenantSecuritySolutionMultiTenantScannerIdentity `
                                                -DisplayName <AADAppDisplayName> 

# -----------------------------------------------------------------#
# Step 2: Save ApplicationId and ObjectId generated for AAD App using the above command. This will be used in AzTS Soln installation later.
# -----------------------------------------------------------------#

# Application id of the App
$appDetails.ApplicationId

# Object id of the App
$appDetails.ObjectId 

#Secret of the App, 
#DON'T PRINT VALUE IN CONSOLE, Just use variable as is in next step
#$appDetails.Secret

```

**Parameter details:**
|Param Name|Description|Required?
|----|----|----|
| DisplayName| Display name of the Scanner Identity (AAD Application) to be created.| Yes|
|ObjectId| Object Id of the AAD Application, if want to use any existing App.|No|

</br>

**4.b. Securely store central scanning App credentials:** Credentials generated for central scanning App in the above step need to be stored securely in KeyVault. Following command will create a Key Vault and store App's credentials as secret.  
</br>

``` PowerShell

$secretStoreDetails= Set-AzSKTenantSecuritySolutionSecretStorage `
                            -SubscriptionId <SubscriptionId> `
                            -ResourceGroupName <RGName> `
                            -Location <Location>`
                            -KeyVaultName <KeyVaultName> `
                            -AADAppId $appDetails.ApplicationId`
                            -AADAppHostTenantId <HostTenantId>`
                            -AADAppPasswordCredential $appDetails.Secret

```

> **Note:** 
> 1. _As a security best practice, we recommend storing central scanning identity credentials (i.e. Key Vault holding secret/credentials) in an isolated subscription with limited permission to secure access to credentials._
> 
> 2. _If you provide any existing Key Vault details in above command, all existing access policies will be cleaned as only AzTS solution is intended to have access on this Key Vault._
>
> </br>

**Parameter details:**
|Param Name|Description|Required?
|----|----|----|
| SubscriptionId| Subscription Id where Key Vault resource to be created.| Yes|
| ResourceGroupName| Name of the Resource Group where Key Vault resource to be created.|Yes|
| Location| Location for Key Vault resource. Default is 'EastUS2'.| False|
| KeyVaultName| Name of the Key Vault resource to be created.|Yes|
| AADAppId| Central scanning App's Application Id.| Yes|
| AADAppHostTenantId| AzTS solution Host Tenant Id.|Yes|
| AADAppPasswordCredential|  Central scanning App's password credentials.|Yes|

</br>

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)

### **Step 5 of 7. Create Azure AD application for secure authentication**

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

# Add Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud
$AzureEnvironmentName = <AzureEnvironmentName>

$ADApplicationDetails = Set-AzSKTenantSecurityADApplication -SubscriptionId $HostSubscriptionId -ScanHostRGName $HostResourceGroupName -AzureEnvironmentName $AzureEnvironmentName

# -----------------------------------------------------------------#
# Step 2: Save WebAPIAzureADAppId and UIAzureADAppId generated for Azure AD application using the below command. This will be used in AzTS Soln installation. 
# -----------------------------------------------------------------#

# Azure AD application client (application) ids 
$ADApplicationDetails.WebAPIAzureADAppId
$ADApplicationDetails.UIAzureADAppId 

```

</br>

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)

### **Step 6 of 7. Run Setup Command**
You need to run install command present as part setup script with host subscription Id (subscription where scanning infra resources will get created). Setup will create infra resources and schedule daily security control scan on target subscriptions. Please validate you have 'Owner' access on the subscription where the solution needs to be installed.

> **Note:**
> 1. _Setup may take up to 5 minutes to complete._
> 2. _For better performance, we recommend using one location for keeping central scanning identity credentials and resources which will be created in the following installation steps using the `Install-AzSKTenantSecuritySolution` cmdlet._
> 3. _To restrict network traffic and to ensure that all inbound communication to critical backend resources of AzTS solution are routed through private network(VNet), install AzTS setup with **VNet integration**. For this you will need to run the installation command `Install-AzSKTenantSecuritySolution` with `-EnableVnetIntegration` switch._
> 4. _AzTSDeploymentTemplate provides capability to deploy AzTS UI and API which can be used to see compliance summary against each subscription and scan your subscription(s) manually. To deploy AzTS UI and API run installation command `Install-AzSKTenantSecuritySolution` with `-EnableAzTSUI` switch._
> 5. _If you want to provide additional security to AzTS UI and configure custom rules for accessing public endpoints, you must enable Web Application Firewall (WAF). To know more about WAF visit [here](https://docs.microsoft.com/en-us/azure/web-application-firewall/overview). To enable WAF for AzTS UI and API run the installation command `Install-AzSKTenantSecuritySolution` with `-EnableAzTSUI` and `-EnableWAF` switch._
>
> &nbsp;

Run installation command with required parameters. 

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
                -ScanIdentitySecretUri <KeyVaultSecretUrl> `
                -EnableMultiTenantScan `
                -WebAPIAzureADAppId <WebAPIAzureADApplicationId> `
                -UIAzureADAppId <UIAzureADApplicationId> `
                [-AzureEnvironmentName AzureCloud] `
                [-ScanIdentityHasGraphPermission:$true] `
                -SendAlertNotificationToEmailIds @('<EmailId1>', '<EmailId2>', '<EmailId3>') `
                [-EnableAutoUpdater] `
                -EnableAzTSUI `
                [-EnableVnetIntegration] `
                [-EnableWAF] `
                -Verbose

  <# Note : Parameters that are provided in square brackets[] in the above installation command are optional parameters. UIAzureADAppId and WebAPIAzureADAppId are mandatory parameters if you are enabling AzTSUI and WAF.
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
                    -ScanIdentitySecretUri 'https://keyvault-name.azure.net/secrets/SecretName/' `
                    -Location EastUS2 `
                    -EnableAzTSUI `
                    -EnableMultiTenantScan `
                    -UIAzureADAppId '000000yy-00yy-00yy-00yy-0000000000yy' `
                    -WebAPIAzureADAppId '000000xx-00xx-00xx-00xx-0000000000xx' `
                    -AzureEnvironmentName AzureCloud `
                    -ScanIdentityHasGraphPermission:$true `
                    -SendAlertNotificationToEmailIds @('User1@Contoso.com', 'User2@Contoso.com', 'User3@Contoso.com') `
                    -EnableAutoUpdater `
                    -Verbose


<#

For '-ScanIdentitySecretUri' parameter, 
          (a) use value created for "$secretStoreDetails.outputs.secretURI.value" from prerequisite section step 4.
                              OR
          (b) Run Set-AzSKTenantSecuritySolutionSecretStorage command provided in step 4.b.
                              OR
          (c) you can get this secret identifier by going into Azure Portal --> Subscription where key vault resource created --> KeyVaultHostingRG --> Click on Key Vault resource --> Secrets --> Select 'SecretName' --> Copy 'Secret Identifier'.

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
|SubscriptionId|Hosting subscription id where Azure Tenant solution will be deployed. |TRUE|
|ScanHostRGName| Name of ResourceGroup where setup resources will be created. |TRUE|
|ScanIdentitySecretUri| Key Vault SecretUri of the Scanner App's credentials.  |TRUE|
|Location|Location where all resources will get created. |TRUE|
|EnableMultiTenantScan | Switch to enable multi-tenant scanning. |TRUE|
|WebAPIAzureADAppId| Application (client) id of the Azure AD application to be used by the API. | FALSE |
|UIAzureADAppId | Application (client) id of the Azure AD application to be used by the UI. | FALSE|
|SendAlertNotificationToEmailIds| Send monitoring alerts notification to the specified email ids. | TRUE |
|AzureEnvironmentName| Name of the Azure cloud where Azure Tenant solution will be deployed. The default value is AzureCloud.|FALSE|
|ScanIdentityHasGraphPermission|Switch to enable features dependent on Microsoft Graph API from the scan. Set this to false if user-assigned managed identity does not have Graph permission. The default value is false.|FALSE|
|EnableAutoUpdater | Switch to enable AzTS auto updater. Autoupdater helps to get latest feature released for AzTS components covering updates for security controls. If this is disabled, you can manually update AzTS components by re-running setup command.|FALSE|
|EnableAzTSUI | Switch to enable AzTS UI. AzTS UI is created to see compliance status for subscription owners and perform adhoc scan. |FALSE|
|EnableVnetIntegration | Switch to enable VNet integration for AzTS setup. Enabling VNet integration for AzTS setup, ensures that all critical resources like storage, function apps, log analytics workspace etc that are part of AzTS setup, are not accessible over public internet. |FALSE|
|EnableWAF | Switch to enable Web Application Firewall (WAF) for AzTS UI and API. To provide additional security and to protect web applications from common exploits and vulnerabilities, it is recommended to enable WAF. By default [managed rule sets](https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview#azure-managed-rule-sets) are configured and prevention mode is enabled for your WAF policy. You can create [custom rules](https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-create-portal#custom-rules) for your WAF policy as per your requirement. |FALSE|
|Verbose| Switch used to output detailed log |FALSE|

</br>

> **Note:** 
>
> 1. Tenant Security Solution does not support customization of the App Service name.
>
> 2. By default max timeout limit of function app is set to 9 minutes. This can be modified based on the requirement of your organization. To increase function timeout, you can upgrade to a higher App Service plan and use the `AzureFunctionsJobHost__functionTimeout` app setting in App Service to set the timeout value.
>
> </br>

</br>

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)

### **Step 7 of 7. Grant required permission to internal MI**
AzTS Solution creates an Internal MI identity used to perform internal operations such as access LA workspace and storage for sending scan result. This internal MI needs following two additional permissions:
1. Provide 'Reader' access and 'Secret Read' permission over Key Vault.
2. Grant MS Graph read access.

**7.a. Provide access over Key Vault:** 
Internal MI need permission over Key Vault & Secret created in Step #4 to access central scanning identity's credential. Run follow command to grant required permissions:

``` PowerShell
  # Grant 'Read' acces over Key Vault and 'Secret Read' access policy
  Grant-AzSKAccessOnKeyVaultToUserAssignedIdentity `
                      -SubscriptionId  <HostSubIdForKeyVault>  `
                      -ResourceId <KeyVaultResourceId> `
                      -UserAssignedIdentityObjectId $InternalIdentityObjectId 

  <#

    For '-ResourceId' parameter, 
          (a) use value created for "$secretStoreDetails.outputs.keyVaultResourceId.value" from prerequisite section step 4.
                              OR
          (b) Run Set-AzSKTenantSecuritySolutionSecretStorage command provided in step 4.b.
                              OR
          (c) you can get this resources id by going into Azure Portal --> Subscription where key vault resource created --> KeyVaultHostingRG --> Click on Key Vault resource --> Properties --> Copy 'ResourceId'.

#>

```

**7.b. Grant MS Graph read access:**  Internal MI is also used by AzTS UI to read the list of security groups that the user is a member of. For this purpose, internal MI requires 'User.Read.All' permission.
</br>

``` PowerShell
  # Grant 'User.Read.All' permission to internal MI
  Grant-AzSKGraphPermissionToUserAssignedIdentity `
                      -UserAssignedIdentityObjectId  $InternalIdentityObjectId  `
                      -MSGraphPermissionsRequired @('User.Read.All')

```

> **Note:** 
> _This step requires admin consent. To complete this step, the signed-in user must be a member of one of the following administrator roles: </br> Global Administrator or Privileged Role Administrator.</br>If you do not have the required permission, please contact your administrator to get 'User.Read.All' permission for the internal MI in Azure Active Directory using [this PowerShell script](../Scripts/ScriptToGrantGraphPermissionToInternalMI.ps1?raw=1). To run this script, you need to provide the object id of the user-assigned managed identity (internal MI) created in this step._
> 

</br>

**Congratulations! Installation is complete with this step.**

</br>

**This setup process does not onboard any tenant by default for scanning, to scan any tenant you need to follow onboarding process present [here](MultiTenantSetupWithAADApp.md#2-onboard-tenants-for-scanning)**
</br>

**Next steps:**

To view scan result in AzTS UI:
1. Copy the AzTS UI link provided at the end of the installation command.
2. We recommend creating a custom domain name for your UI. For steps to create a custom domain, refer to this [link](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain).
3. [Onboard tenants](MultiTenantSetupWithAADApp.md#2-onboard-tenants-for-scanning) for scanning.
4. AzTS UI is \*not\* available for use immediately after installation, as it requires one round of scan to complete to show the scan result in UI. Automated AzTS scans are configured to start at approximately 1:00 AM UTC. Therefore, you can use the [On-Demand scan](/01-Setup%20and%20getting%20started/README.md#2-manually-trigger-azts-on-demand-scan-for-entire-tenant) command to trigger the scan immediately after installation.
5. Update org-subscription mapping for your subscription(s) in AzTS UI. By default, there is no service mapping for your subscription. Therefore, you see the 'Unknown' value in the Service Filter dropdown in AzTS UI. To add service mapping, follow the steps provided here: 
    - [Step 1: Prepare your org-subscription mapping](/02-Monitoring%20security%20using%20AzTS/README.md#step-1-prepare-your-org-subscription-mapping)
    - [Step 2: Upload your mapping to the Log Analytics (LA) workspace](/02-Monitoring%20security%20using%20AzTS/README.md#step-2-upload-your-mapping-to-the-log-analytics-la-workspace) 

</br>

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)



## **2. Onboard tenants for scanning**
To onboard any tenant to AzTS scanner, following **steps need to be performed for each tenant**:

1. [Connect with Active Directory of target tenant](MultiTenantSetupWithAADApp.md#step-1-of-5-connect-with-active-directory-of-target-tenant)
2. [Create SPN for central scanning identity (AAD App) in target tenant](MultiTenantSetupWithAADApp.md#step-2-of-5-create-spn-for-central-aad-app-in-target-tenant)
3. [Grant 'Reader' Access to SPN on Azure subscriptions](MultiTenantSetupWithAADApp.md#step-3-of-5-grant-reader-access-to-spn-on-azure-subscriptions)
4. [Grant Graph permissions to SPN in each Tenant/Directory](MultiTenantSetupWithAADApp.md#step-4-of-5-grant-graph-permissions-to-spn-in-target-tenant)
5. [Enable scanning for target tenant](MultiTenantSetupWithAADApp.md#step-5-of-5-enable-scanning-for-target-tenant)


### **Step 1 of 5. Connect with Active Directory of target tenant**

First you need to login into Azure Active Directory (AAD) of target tenant which you want to onboard using the following PowerShell command.

``` PowerShell
# Clear existing login, if any

Disconnect-AzAccount
Disconnect-AzureAD

# Connect to AzureAD and AzAccount
# Note: Tenant Id *must* be specified when connecting to Azure AD and AzAccount

$TenantId = "<TargetTenantId>"
Connect-AzAccount -Tenant $TenantId
Connect-AzureAD -TenantId $TenantId
```

### **Step 2 of 5. Create SPN for central AAD App in target tenant**

Service principal (SPN) for the central scanning App (multi-tenant App created as part of AzTS setup) need to be created in target tenant (tenant to be onboarded for scan). `Create-AzSKTenantSecuritySolutionMultiTenantIdentitySPN` command creates SPN for the central scanning App:

``` PowerShell
# -----------------------------------------------------------------#
#  Create Service principal (SPN) for the central scanning App
# -----------------------------------------------------------------#

$spnDetails = Create-AzSKTenantSecuritySolutionMultiTenantIdentitySPN `
                                                -AppId <Scanning Apps Unique Identifier> 

# -----------------------------------------------------------------#
#  Save SPN's Object Id
$spnDetails.ObjectId

```

**Parameter details:**
|Param Name|Description|Required?
|----|----|----|
| AppId| Unique identifier of the AAD application of which ServicePrincipal need to be created.| Yes|

</br>

### **Step 3 of 5. Grant 'Reader' Access to SPN on Azure subscriptions**
To do the scanning, AzTS solution scanning identity requires 'Reader' access on subscriptions of the target tenant for which scan needs to be performed. Command `Grant-AzSKAzureRoleToMultiTenantIdentitySPN` assigns 'Reader' access to SPN (created in step #2 above) of central scanning identity on target subscriptions. You need to be 'Owner' on target subscription to perform role assignment.

> _Note:_
> 1. _If subscriptions are organized under [Management Groups](https://docs.microsoft.com/en-us/azure/governance/management-groups/overview) (MG), you can assign reader role for SPN using MG role assignment using [Azure Portal](https://docs.microsoft.com/en-us/azure/security-center/security-center-management-groups#assign-azure-roles-to-other-users). For this you need to be 'Owner' on management group level to perform role assignment._
> 
> 2. _All subscriptions and management groups fold up to the one root management group within the directory. To scan all the subscriptions in your tenant, you can assign reader role at root management group scope. Azure AD Global Administrators are the only users who can grant access at this scope._
> 

</br>

``` PowerShell
    Grant-AzSKAzureRoleToMultiTenantIdentitySPN `
                                        -AADIdentityObjectId $spnDetails.ObjectId `
                                        -TargetSubscriptionIds @("SubId1", "SubId2")
```

### **Step 4 of 5. Grant Graph permissions to SPN in target tenant**
AzTS solution scanning identity requires MS Graph permission to read data in your organization's directory, such as users, groups and apps and to validate Role-based access control (RBAC) using Azure AD Privileged Identity Management (PIM). This permission is required for the evaluation of RBAC based controls in AzTS.
</br>

``` PowerShell

# Grant Graph Permission to the to SPN (created in step #2 above) of central scanning identity.
# Required Permission: Global Administrator or Privileged Role Administrator.

Grant-AzSKGraphPermissionToMultiTenantScannerIdentity `
                            -AADIdentityObjectId $spnDetails.ObjectId `
                            -MSGraphPermissionsRequired @("PrivilegedAccess.Read.AzureResources", "Directory.Read.All") `
                            -ADGraphPermissionsRequired @("Directory.Read.All") 

```


> **Note:** 
> 1. _This step requires admin consent. Therefore, the signed-in user must be a member of one of the following administrator roles: Global Administrator or Privileged Role Administrator. If you do not have the required permission, please contact your administrator to get "PrivilegedAccess.Read.AzureResources" and "Directory.Read.All" permission for SPN of central scanning identity in Azure Active Directory._
> 
> 2. _You can proceed without this step, however, the AzTS Soln will run with limited functionality such as the solution will not be able to scan RBAC controls, classic administrator of a subscription will not be able to use the user interface provided by AzTS Soln (AzTS UI) to request on-demand scan, view control failures etc.,_
>
> </br>

### **Step 5 of 5. Enable scanning for target tenant**

This is the final step to onboard target tenant for scanning. Once you have completed above mentioned steps (1-4) for the tenant, you can use [onboarding API](OnboardTenantToAzTS.md#onboarding) to complete the onboarding process and enable security scan for the tenant.

> **Note:** 
> _You can perform this step for multiple tenants in a single go as well to save time. So, if you have multiple tenants, please complete steps #1 to #4 for all tenants and then use [onboarding API](OnboardTenantToAzTS.md#onboarding) to onboard and enable security scanning for mulitple tenants in a single request._
> 


</br>

[Back to top…](MultiTenantSetupWithAADApp.md#setting-up-multi-tenant-azure-tenant-security-azts-solution---step-by-step)

## **3. FAQs**
TBD