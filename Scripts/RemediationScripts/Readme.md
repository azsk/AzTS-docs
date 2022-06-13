# Bulk Remediation Script (BRS)

## On this page:

- [Overview](Readme.md#overview)
- [List of controls with Bulk Remediation Script (BRS) support](Readme.md#list-of-controls-with-bulk-remediation-script-brs-support)
- [How to use Bulk Remediation Script (BRS)](Readme.md#how-to-use-bulk-remediation-script-brs)

## **Overview**
Bulk remediation scripts (BRS) can be used to remediate non-compliant resources/subscription for a control. These scripts are limited to the controls that have relatively lower risk to bulk-remediate.

## **List of controls with Bulk Remediation Script (BRS) support**
- [Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN](Readme.md#azure_apimanagement_authn_use_aad_for_client_authn)
- [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme](Readme.md#Azure_APIManagement_DP_Use_HTTPS_URL_Scheme)
- [Azure_AppService_Config_Disable_Remote_Debugging](Readme.md#Azure_AppService_Config_Disable_Remote_Debugging)
- [Azure_AppService_DP_Dont_Allow_HTTP_Access](Readme.md#Azure_AppService_DP_Dont_Allow_HTTP_Access)
- [Azure_AppService_DP_Use_Secure_TLS_Version](Readme.md#Azure_AppService_DP_Use_Secure_TLS_Version)
- [Azure_CloudService_SI_Disable_RemoteDesktop_Access](Readme.md#Azure_CloudService_SI_Disable_RemoteDesktop_Access)
- [Azure_ContainerRegistry_Config_Enable_Security_Scanning](Readme.md#Azure_ContainerRegistry_Config_Enable_Security_Scanning)
- [Azure_KubernetesService_AuthN_Enabled_AAD](Readme.md#Azure_KubernetesService_AuthN_Enabled_AAD)
- [Azure_RedisCache_DP_Use_SSL_Port](Readme.md#Azure_RedisCache_DP_Use_SSL_Port)
- [Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel](Readme.md#Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel)
- [Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server](Readme.md#Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server)
- [Azure_SQLDatabase_AuthZ_Use_AAD_Admin](Readme.md#Azure_SQLDatabase_AuthZ_Use_AAD_Admin)
- [Azure_SQLDatabase_DP_Enable_TDE](Readme.md#Azure_SQLDatabase_DP_Enable_TDE)
- [Azure_Storage_AuthN_Dont_Allow_Anonymous](Readme.md#Azure_Storage_AuthN_Dont_Allow_Anonymous)
- [Azure_Storage_DP_Encrypt_In_Transit](Readme.md#Azure_Storage_DP_Encrypt_In_Transit)
- [Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities](Readme.md#Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities)
- [Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count](Readme.md#Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count)
- [Azure_Subscription_AuthZ_Remove_Deprecated_Accounts](Readme.md#Azure_Subscription_AuthZ_Remove_Deprecated_Accounts)
- [Azure_Subscription_AuthZ_Remove_Management_Certs](Readme.md#Azure_Subscription_AuthZ_Remove_Management_Certs)
- [Azure_Subscription_Config_MDC_Defender_Plans](Readme.md#Azure_Subscription_Config_MDC_Defender_Plans)
- [Azure_Subscription_Configure_Conditional_Access_for_PIM](Readme.md#Azure_Subscription_Configure_Conditional_Access_for_PIM)

<br />

___ 


## Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN

### Display Name
Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials

### Link to Bulk Remediation Script (BRS)
[Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices](Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](#supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## Azure_APIManagement_DP_Use_HTTPS_URL_Scheme
### Display Name
Ensure API Management service is accessible only over HTTPS

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableHTTPSForAPIsInAPIManagementServices](Remediate-EnableHTTPSForAPIsInAPIManagementServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## Azure_AppService_Config_Disable_Remote_Debugging

### Display Name
Remote debugging should be turned off for Web Applications

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableRemoteDebuggingForAppServices](Remediate-DisableRemoteDebuggingForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports_managed_identity_based_remediation-22) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_AppService_DP_Dont_Allow_HTTP_Access

### Display Name
Use HTTPS for App Services

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableHTTPSForAppServices](Remediate-EnableHTTPSForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_AppService_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in App Service

### Link to Bulk Remediation Script (BRS)
[Remediate-SetAppServiceMinReqTLSVersion](Remediate-SetAppServiceMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_CloudService_SI_Disable_RemoteDesktop_Access

### Display Name
Remote Desktop (RDP) access must be disabled on cloud service roles

### Link to Bulk Remediation Script (BRS)
[Remediate-RemoteDesktopAccess](Remediate-RemoteDesktopAccess.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## Azure_ContainerRegistry_Config_Enable_Security_Scanning

### Display Name
Security scanner identity must be granted access to Container Registry for image scans

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableSecurityScanningForContainerRegistry](Remediate-EnableSecurityScanningForContainerRegistry.ps1)

### Minimum permissions required to run the script
Reader role at subscription level **and** Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_KubernetesService_AuthN_Enabled_AAD

### Display Name
AAD should be enabled in Kubernetes Service

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAADForKubernetesService](Remediate-EnableAADForKubernetesService.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
No

___ 


## Azure_RedisCache_DP_Use_SSL_Port

### Display Name
Non-SSL port must not be enabled

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableNonSSLPortOnRedisCache](Remediate-DisableNonSSLPortOnRedisCache.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel

### Display Name
The ClusterProtectionLevel property must be set to EncryptAndSign

### Link to Bulk Remediation Script (BRS)
[Remediate-SetClusterProtectionLevelForServiceFabric](Remediate-SetClusterProtectionLevelForServiceFabric.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server

### Display Name
Enable advanced data security on your SQL servers

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAdvancedThreatProtectionForSQLServers](Remediate-EnableAdvancedThreatProtectionForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level (If you want to configure certain settings at subscription level, then Contributor role at subscription level)

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## Azure_SQLDatabase_AuthZ_Use_AAD_Admin

### Display Name
Use AAD Authentication for SQL Database

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAADAuthenticationForSQLServers](Remediate-EnableAADAuthenticationForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## Azure_SQLDatabase_DP_Enable_TDE

### Display Name
Transparent data encryption (TDE) must be enabled

### Link to Bulk Remediation Script (BRS)
[Remediate-TransparentDataEncryptionForSQLServers](Remediate-TransparentDataEncryptionForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## Azure_Storage_AuthN_Dont_Allow_Anonymous

### Display Name
Ensure secure access to Storage account containers

### Link to Bulk Remediation Script (BRS)
[Remediate-AnonymousAccessOnContainers](Remediate-AnonymousAccessOnContainers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_Storage_DP_Encrypt_In_Transit

### Display Name
Enable Secure transfer to Storage Accounts

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableEncryptionInTransitForStorageAccounts](Remediate-EnableEncryptionInTransitForStorageAccounts.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Yes

### Supports rollback?
Yes

___ 


## Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities

### Display Name
Remove external accounts from Azure subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-DontUseNonADIdentities](Remediate-DontUseNonADIdentities.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count

### Display Name
Limit access per subscription to 2 or less classic administrators

### Link to Bulk Remediation Script (BRS)
[Remediate-ClassicAdminRoleAssignment](Remediate-ClassicAdminRoleAssignment.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## Azure_Subscription_AuthZ_Remove_Deprecated_Accounts

### Display Name
Remove Orphaned accounts from your subscription(s)

### Link to Bulk Remediation Script (BRS)
[Remediate-InvalidAADObjectRoleAssignments](Remediate-InvalidAADObjectRoleAssignments.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## Azure_Subscription_AuthZ_Remove_Management_Certs

### Display Name
Do not use management certificates

### Link to Bulk Remediation Script (BRS)
[Remediate-DoNotUseManagementCertificates](Remediate-DoNotUseManagementCertificates.ps1)

### Minimum permissions required to run the script
ServiceAdministrator/CoAdministrator role

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## Azure_Subscription_Config_ASC_Defender

### Display Name
Enable all Azure Defender plans in Azure Security Center

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigAzureDefender](Remediate-ConfigAzureDefender.ps1)

### Minimum permissions required to run the script
Contributor role at subscription level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## Azure_Subscription_Configure_Conditional_Access_for_PIM

### Display Name
Enable policy to require PIM elevation from SAW for admin roles in Azure subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigureConditionalAccessPolicyForPIM](Remediate-ConfigureConditionalAccessPolicyForPIM.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 1. Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access </br>2. Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG </br>3. Azure_Subscription_Use_Only_Alt_Credentials

### Display Name
1.Do not grant permanent access for privileged subscription level roles </br>2.Do not grant permanent access for privileged roles at resource group level </br>3.Use Smart-Card ALT (SC-ALT) accounts to access critical roles on subscription and resource groups

### Link to Bulk Remediation Script (BRS)
[Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments](/Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments/Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#Supports_managed_identity_based_remediation) based remediation**
Restricted to 'User' account type

### Supports rollback?
No

___ 


</br>

## Supports managed identity based remediation
Both System assigned and User assigned managed identities are supported.

* To connect Azure Account using **System assigned managed identity**, use the following command:</br>
  Connect-AzAccount -Identity

* To connect Azure Account using **User assigned managed identity**, use the following command:</br>
  Connect-AzAccount -Identity -AccountId 'object-id'
</br>

## **How to use Bulk Remediation Script (BRS)**

### Load remediation script to fix failed controls of Azure Tenant Security Solution - Step by Step
In this section, we will walk through the steps of loading remediation script.

**Note:** You can download remediation script present [here](../../TemplateFiles/RemediationScripts.zip?raw=1)

Loading script in PowerShell session is divided into four steps:

### **Step 1 of 4. Validate prerequisites on machine**  

  i) Installation steps are supported using following OS options: 	

  - Windows 10
  - Windows Server 2019

  ii) PowerShell 5.0 or higher:

  All setup steps will be performed with the help of PowerShell ISE console. If you are unaware of PowerShell ISE, refer [link](https://github.com/azsk/DevOpsKit-docs/blob/master/00b-Getting-Started/GettingStarted_PowerShellTipsAzSK.md) to get basic understanding.
  Ensure that you are using Windows OS and have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.)
  If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).

  ![PowerShell Version](../../Images/00_PS_Version.png)

### **Step 2 of 4. Installing Az Modules:**

Az modules contain cmdlet to connect to Az Account.
Install Az PowerShell Modules using below command. 
For more details of Az Modules refer [link](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps)

``` PowerShell
# Install Az Modules
Install-Module -Name Az.Accounts -AllowClobber -Scope CurrentUser -repository PSGallery
```
### **Step 3 of 4. Download and extract remediation package**
 
 Remediation package mainly contains:
 1. **RemediationScripts** which contains PowerShell scripts to remediate AzTS controls.

If you have already downloaded the remediation package zip, you can start from step (3.d).

3.a. Download remediation package zip from [here](../../TemplateFiles/RemediationScripts.zip?raw=1) to your local machine. </br>

3.b. Extract zip to local folder location. <br/>

3.c. Unblock the content. The below command will help to unblock files. <br/>

  ``` PowerShell
  Get-ChildItem -Path "<Extracted folder path>" -Recurse |  Unblock-File 
  ```

3.d. Point current path to downloaded script folder location and load remediation script in PowerShell session
``` PowerShell
# Point current path to location where script is downloaded and load script from folder

CD "<LocalExtractedFolderPath>"

# Before loading remediation script in current session, please connect to AzAccount
Connect-AzAccount

# Load remediation script in session
. ".\<RemediationScriptFileName>.ps1"

# Note: Make sure you copy  '.' present at the start of line.
```

**Step 4 of 4. Execute remediation scripts:**

After completing above mentioned steps, open remediation script in PowerShell and follow instructions as per comments present in each script.
