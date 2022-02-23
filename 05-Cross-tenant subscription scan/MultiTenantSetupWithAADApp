> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

</br>

# Setting up Azure Tenant Security (AzTS) Solution - Step by Step
 
</br>

## On this page:
  - [Steps to install multi tenant AzTS Solution](README.md#1-steps-to-install-multi-tenant-AzTS-solution)
  - [Onboard individual tenants](README.md#2onboard-individual-tenants)
  - [FAQs](README.md#faqs)

--------------------------------------------------
</br>

## **1. Steps to install multi tenant AzTS Solution**

In this section, we will walk through the steps of setting up multi tenant AzTS Solution with central AAD App based scanning model. This setup can take up to 30 minutes.

This setup is divided into following seven steps:

1. [Validate prerequisites on machine](README.md#step-1-of-6-validate-prerequisites-on-machine)
2. [Installing required Az modules](README.md#step-2-of-6-installing-required-az-modules)
3. [Download and extract deployment package](README.md#step-3-of-6-download-and-extract-deployment-package)
4. [Setup central scanning managed identity](README.md#step-4-of-6-setup-central-scanning-managed-identity)
5. [Create Azure AD application for secure authentication](README.md#step-5-of-6-create-azure-ad-application-for-secure-authentication)
6. [Run Setup Command](README.md#step-6-of-6-run-setup-command)
7. [Grant required permission to internal MI](README.md#step-6-of-6-run-setup-command)

> _**Note**: You will need help of Azure Active Directory (AD) administrator in step 4, 5 and 6 to grant Microsoft.Graph permission._

Let's start!

### **Step 1 of 7. Validate prerequisites on machine**  

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

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

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

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

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

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 4 of 7. Setup central scanning identity**  

The AzTS setup provisions your subscriptions with the ability to do daily scans for security controls.
To do the scanning, it requires a central multi-tenant AAD (Azure Active Directory) application in Host tenant. Later SPN (Service principal) of the same applicaton needs to be created in each target tenant and will have 'reader' access on subscriptions in each target tenant.

</br>

Before creating central multi-tenant AAD app, please log in to Azure account and Azure Active Directory (AD) where you want to host the AzTS solution using the following PowerShell command.

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

 **4.a. Create central multi tenant AAD application for scanning:** 
 The PowerShell command creates a multi tenant AAD application and new secret (with 6 months expiry). You should have permission to create new multi tenant AAD application in host tenant. 


> **Note:** <br> _As a security best practice, please do not put secret in any local file or any other place exept Key Vault._

``` PowerShell
# -----------------------------------------------------------------#
# Step 1: Create central scanning user-assigned managed identity
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
| DisplayName| Display Name of the Scanner Identity (AAD Application) to be created.| Yes|
|ObjectId| Object Id of the AAD Application, if want to use any existing App.|No|

</br>

**4.b. Securely store central scanning App credentials:** Credentials generated for central scanning App in the above step need to be stoared securely in KeyVault. Following command will create a Key Vault and store App's credentials as secret.  
</br>

``` PowerShell

Set-AzSKTenantSecuritySolutionSecretStorage `
                            -SubscriptionId <SubscriptionId> `
                            -ResourceGroupName <RGName> `
                            -Location <Location>`
                            -KeyVaultName <KeyVaultName> `
                            -AADAppId $appDetails.ApplicationId`
                            -AADAppHostTenantId <HostTenantId>`
                            -AADAppPasswordCredential $appDetails.Secret

```

> **Note:** 
> 1. _As a security best practice, we recommend storing central scanning identity credentials in an isolated subscription with limited permission to secure access to this identity._
> 
> 2. _If you provide any existing Key Vault details in above command, all existing access policies will be cleaned as only AzTS solution is intended to have access on this Key Vault.,_
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

[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

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



### **Step 6 of 7. Create Azure AD application for secure authentication**

TBD
</br>
[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

### **Step 7 of 7. Grant required permission to internal MI**

TBD
</br>
[Back to top…](README.md#setting-up-azure-tenant-security-azts-solution---step-by-step)

## **2. Onboard individual tenants**
To onboard any tenant to AzTS scanner, following four steps need to be performed for each tenant to be onboarded:

1. [Login into AAD of target tenant](README.md#step-1-of-6-validate-prerequisites-on-machine)
1. [Create SPN for central AAD App in each Tenant/Directory](README.md#step-1-of-6-validate-prerequisites-on-machine)
2. [Grant Graph permissions to SPN in each Tenant/Directory](README.md#step-2-of-6-installing-required-az-modules)
3. [Grant 'Reader' Access to SPN on Azure subscriptions](README.md#step-3-of-6-download-and-extract-deployment-package)

### **Step 1 of 4. Login into AAD of target tenant**

First you need to login into Azure Active Directory (AD) of target tenant which you want to onboard using the following PowerShell command.

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

### **Step 2 of 4. Create SPN for central AAD App in each Tenant/Directory**

The central scanning App created as part of setup need to be instantiated (i.e. Service prinicipal aka SPN needs to be created) in each tenant. `Create-AzSKTenantSecuritySolutionMultiTenantIdentitySPN` command creates SPN for the central scanning App:

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

### **Step 3 of 4. Grant Graph permissions to SPN in each Tenant/Directory**

``` PowerShell
    Grant-AzSKGraphPermissionToMultiTenantScannerIdentity
```

### **Step 4 of 4. Grant 'Reader' Access to SPN on Azure subscriptions**
``` PowerShell
    Grant-AzSKAzureRoleToMultiTenantIdentitySPN
```


Once you have completed above mentioned steps (1-4), you can use [onboarding API](LinkTBD) to complete the onboarding process. 

## **3. FAQs**
TBD