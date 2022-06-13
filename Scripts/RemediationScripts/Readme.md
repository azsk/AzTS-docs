# Bulk Remediation Script (BRS)

## On this page:

- [Overview](README.md#overview)
- [BRS supported control list](README.md#brs_supported_control_list)
- [How to use BRS](README.md#how_to_use_brs)

-----------------

## **Overview**
Bulk remediation scripts (BRS) can be used to remediate non-compliant resources/subscription for a control. These scripts are limited to the controls that have relatively lower risk to bulk-remediate.

## **List of controls with Bulk remediation script (BRS) support**
|Control Id|Control Name|Link to BRS|Minimum permissions required to run the script|Supports managed identity based remediation**|Supports rollback?|
|---|---|---|---|---|---|
|Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN|Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials|[Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices](Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices.ps1)|Contributor role at resource level|Restricted to 'User' account type.|No|
|Azure_APIManagement_DP_Use_HTTPS_URL_Scheme|Ensure API Management service is accessible only over HTTPS|[Remediate-EnableHTTPSForAPIsInAPIManagementServices](Remediate-EnableHTTPSForAPIsInAPIManagementServices.ps1)|Contributor role at resource level|Restricted to 'User' account type.|Yes|
|Azure_AppService_Config_Disable_Remote_Debugging|Remote debugging should be turned off for Web Applications|[Remediate-DisableRemoteDebuggingForAppServices](Remediate-DisableRemoteDebuggingForAppServices.ps1)|Contributor role at resource level|Yes|Yes|
|Azure_AppService_DP_Dont_Allow_HTTP_Access|Use HTTPS for App Services|[Remediate-EnableHTTPSForAppServices](Remediate-EnableHTTPSForAppServices.ps1)|Contributor role at resource level|Yes|Yes|
|Azure_AppService_DP_Use_Secure_TLS_Version|Use Approved TLS Version in App Service|[Remediate-SetAppServiceMinReqTLSVersion](Remediate-SetAppServiceMinReqTLSVersion.ps1)|Contributor role at resource level|Yes|Yes|
|Azure_CloudService_SI_Disable_RemoteDesktop_Access|Remote Desktop (RDP) access must be disabled on cloud service roles|[Remediate-RemoteDesktopAccess](Remediate-RemoteDesktopAccess.ps1)|Contributor role at resource level|Restricted to 'User' account type.|No|
|Azure_ContainerRegistry_Config_Enable_Security_Scanning|Security scanner identity must be granted access to Container Registry for image scans|[Remediate-EnableSecurityScanningForContainerRegistry](Remediate-EnableSecurityScanningForContainerRegistry.ps1)|Reader role at subscription level **and** Contributor role at resource level |Yes|Yes|
|Azure_KubernetesService_AuthN_Enabled_AAD|AAD should be enabled in Kubernetes Service|[Remediate-EnableAADForKubernetesService](Remediate-EnableAADForKubernetesService.ps1)|Contributor role at resource level|Yes|No|
|Azure_RedisCache_DP_Use_SSL_Port|Non-SSL port must not be enabled|[Remediate-DisableNonSSLPortOnRedisCache](Remediate-DisableNonSSLPortOnRedisCache.ps1)|Contributor role at resource level|Yes|Yes|
|Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel|The ClusterProtectionLevel property must be set to EncryptAndSign|[Remediate-SetClusterProtectionLevelForServiceFabric](Remediate-SetClusterProtectionLevelForServiceFabric.ps1)|Contributor role at resource level|Yes|Yes|
|Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server|Enable advanced data security on your SQL servers|[Remediate-EnableAdvancedThreatProtectionForSQLServers](Remediate-EnableAdvancedThreatProtectionForSQLServers.ps1)|Contributor role at resource level (If you want to configure certain settings at subscription level, then Contributor role at subscription level)|Restricted to 'User' account type.|Yes|
|Azure_SQLDatabase_AuthZ_Use_AAD_Admin|Use AAD Authentication for SQL Database|[Remediate-EnableAADAuthenticationForSQLServers](Remediate-EnableAADAuthenticationForSQLServers.ps1)|Contributor role at resource level|Restricted to 'User' account type.|Yes|
|Azure_SQLDatabase_DP_Enable_TDE|Transparent data encryption (TDE) must be enabled|[Remediate-TransparentDataEncryptionForSQLServers](Remediate-TransparentDataEncryptionForSQLServers.ps1)|Contributor role at resource level|Restricted to 'User' account type.|Yes|
|Azure_Storage_AuthN_Dont_Allow_Anonymous|Ensure secure access to Storage account containers|[Remediate-AnonymousAccessOnContainers](Remediate-AnonymousAccessOnContainers.ps1)|Contributor role at resource level|Yes|Yes|
|Azure_Storage_DP_Encrypt_In_Transit|Enable Secure transfer to Storage Accounts|[Remediate-EnableEncryptionInTransitForStorageAccounts](Remediate-EnableEncryptionInTransitForStorageAccounts.ps1)|Contributor role at resource level|Yes|Yes|
|Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities|Remove external accounts from Azure subscriptions|[Remediate-DontUseNonADIdentities](Remediate-DontUseNonADIdentities.ps1)|Owner/User Access Administrator role at subscription level|Restricted to 'User' account type.|Yes|
|Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count|Limit access per subscription to 2 or less classic administrators|[Remediate-ClassicAdminRoleAssignment](Remediate-ClassicAdminRoleAssignment.ps1)|Owner/User Access Administrator role at subscription level|Restricted to 'User' account type.|Yes|
|Azure_Subscription_AuthZ_Remove_Deprecated_Accounts|Remove Orphaned accounts from your subscription(s)|[Remediate-InvalidAADObjectRoleAssignments](Remediate-InvalidAADObjectRoleAssignments.ps1)|Owner/User Access Administrator role at subscription level|Restricted to 'User' account type.|No|
|Azure_Subscription_AuthZ_Remove_Management_Certs|Do not use management certificates|[Remediate-DoNotUseManagementCertificates](Remediate-DoNotUseManagementCertificates.ps1)|ServiceAdministrator/CoAdministrator role|Restricted to 'User' account type.|No|
|Azure_Subscription_Config_ASC_Defender|Enable all Azure Defender plans in Azure Security Center|[Remediate-ConfigAzureDefender](Remediate-ConfigAzureDefender.ps1)|Contributor role at subscription level|Restricted to 'User' account type.|Yes|
|Azure_Subscription_Configure_Conditional_Access_for_PIM|Enable policy to require PIM elevation from SAW for admin roles in Azure subscriptions|[Remediate-ConfigureConditionalAccessPolicyForPIM](Remediate-ConfigureConditionalAccessPolicyForPIM.ps1)|Owner/User Access Administrator role at subscription level|Restricted to 'User' account type.|Yes|
|1. Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access </br>2. Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG </br>3. Azure_Subscription_Use_Only_Alt_Credentials|1. Do not grant permanent access for privileged subscription level roles </br>2. Do not grant permanent access for privileged roles at resource group level </br>3. Use Smart-Card ALT (SC-ALT) accounts to access critical roles on subscription and resource groups|[Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments](/Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments/Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments.ps1)|Owner/User Access Administrator role at subscription level|Restricted to 'User' account type.|No|

</br>
**Both System assigned and User assigned managed identities are supported.

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
