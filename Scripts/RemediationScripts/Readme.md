# Bulk Remediation Script (BRS)

## On this page:

- [Overview](Readme.md#overview)
- [List of controls with Bulk Remediation Script (BRS) support](Readme.md#list-of-controls-with-bulk-remediation-script-brs-support)
- [How to use Bulk Remediation Script (BRS)](Readme.md#how-to-use-bulk-remediation-script-brs)

## **Overview**
Bulk remediation scripts (BRS) can be used to remediate non-compliant resources/subscription for a control. These scripts are limited to the controls that have relatively lower risk to bulk-remediate.

## **List of controls with Bulk Remediation Script (BRS) support**
1. [Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN](Readme.md#1-azure_apimanagement_authn_use_aad_for_client_authn)
2. [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme](Readme.md#2-Azure_APIManagement_DP_Use_HTTPS_URL_Scheme)
3. [Azure_AppService_Config_Disable_Remote_Debugging](Readme.md#3-Azure_AppService_Config_Disable_Remote_Debugging)
4. [Azure_AppService_DP_Dont_Allow_HTTP_Access](Readme.md#4-Azure_AppService_DP_Dont_Allow_HTTP_Access)
5. [Azure_AppService_DP_Use_Secure_TLS_Version](Readme.md#5-Azure_AppService_DP_Use_Secure_TLS_Version)
6. [Azure_CloudService_SI_Disable_RemoteDesktop_Access](Readme.md#6-Azure_CloudService_SI_Disable_RemoteDesktop_Access)
7. [Azure_ContainerRegistry_Config_Enable_Security_Scanning](Readme.md#7-Azure_ContainerRegistry_Config_Enable_Security_Scanning)
8. [Azure_KubernetesService_AuthN_Enabled_AAD](Readme.md#8-Azure_KubernetesService_AuthN_Enabled_AAD)
9. [Azure_RedisCache_DP_Use_SSL_Port](Readme.md#9-Azure_RedisCache_DP_Use_SSL_Port)
10. [Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel](Readme.md#10-Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel)
11. [Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server](Readme.md#11-Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server)
12. [Azure_SQLDatabase_AuthZ_Use_AAD_Admin](Readme.md#12-Azure_SQLDatabase_AuthZ_Use_AAD_Admin)
13. [Azure_SQLDatabase_DP_Enable_TDE](Readme.md#13-Azure_SQLDatabase_DP_Enable_TDE)
14. [Azure_Storage_AuthN_Dont_Allow_Anonymous](Readme.md#14-Azure_Storage_AuthN_Dont_Allow_Anonymous)
15. [Azure_Storage_DP_Encrypt_In_Transit](Readme.md#15-Azure_Storage_DP_Encrypt_In_Transit)
16. [Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities](Readme.md#16-Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities)
17. [Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count](Readme.md#17-Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count)
18. [Azure_Subscription_AuthZ_Remove_Deprecated_Accounts](Readme.md#18-Azure_Subscription_AuthZ_Remove_Deprecated_Accounts)
19. [Azure_Subscription_AuthZ_Remove_Management_Certs](Readme.md#19-Azure_Subscription_AuthZ_Remove_Management_Certs)
20. [Azure_Subscription_Config_MDC_Defender_Plans](Readme.md#20-Azure_Subscription_Config_MDC_Defender_Plans)
21. [Azure_Subscription_Configure_Conditional_Access_for_PIM](Readme.md#21-Azure_Subscription_Configure_Conditional_Access_for_PIM)
22. [Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access](Readme.md#22-Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access)
23. [Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG](Readme.md#23-Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG)
24. [Azure_Subscription_Use_Only_Alt_Credentials](Readme.md#24-Azure_Subscription_Use_Only_Alt_Credentials)
25. [Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port](Readme.md#25-Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port)
26. [Azure_AppService_DP_Use_Secure_FTP_Deployment](Readme.md#26-Azure_AppService_DP_Use_Secure_FTP_Deployment)




29. [Azure_FrontDoor_NetSec_Enable_WAF_Configuration](Readme.md#25-Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port)

<br />

___ 


## 1. Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN

### Display Name
Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials

### Link to Bulk Remediation Script (BRS)
[Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices](Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## 2. Azure_APIManagement_DP_Use_HTTPS_URL_Scheme
### Display Name
Ensure API Management service is accessible only over HTTPS

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableHTTPSForAPIsInAPIManagementServices](Remediate-EnableHTTPSForAPIsInAPIManagementServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 3. Azure_AppService_Config_Disable_Remote_Debugging

### Display Name
Remote debugging should be turned off for Web Applications

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableRemoteDebuggingForAppServices](Remediate-DisableRemoteDebuggingForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 4. Azure_AppService_DP_Dont_Allow_HTTP_Access

### Display Name
Use HTTPS for App Services

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableHTTPSForAppServices](Remediate-EnableHTTPSForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 5. Azure_AppService_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in App Service

### Link to Bulk Remediation Script (BRS)
[Remediate-SetAppServiceMinReqTLSVersion](Remediate-SetAppServiceMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 6. Azure_CloudService_SI_Disable_RemoteDesktop_Access

### Display Name
Remote Desktop (RDP) access must be disabled on cloud service roles

### Link to Bulk Remediation Script (BRS)
[Remediate-RemoteDesktopAccess](Remediate-RemoteDesktopAccess.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## 7. Azure_ContainerRegistry_Config_Enable_Security_Scanning

### Display Name
Security scanner identity must be granted access to Container Registry for image scans

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableSecurityScanningForContainerRegistry](Remediate-EnableSecurityScanningForContainerRegistry.ps1)

### Minimum permissions required to run the script
Reader role at subscription level **and** Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 8. Azure_KubernetesService_AuthN_Enabled_AAD

### Display Name
AAD should be enabled in Kubernetes Service

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAADForKubernetesService](Remediate-EnableAADForKubernetesService.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
No

___ 


## 9. Azure_RedisCache_DP_Use_SSL_Port

### Display Name
Non-SSL port must not be enabled

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableNonSSLPortOnRedisCache](Remediate-DisableNonSSLPortOnRedisCache.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 10. Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel

### Display Name
The ClusterProtectionLevel property must be set to EncryptAndSign

### Link to Bulk Remediation Script (BRS)
[Remediate-SetClusterProtectionLevelForServiceFabric](Remediate-SetClusterProtectionLevelForServiceFabric.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 11. Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server

### Display Name
Enable advanced data security on your SQL servers

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAdvancedThreatProtectionForSQLServers](Remediate-EnableAdvancedThreatProtectionForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level (If you want to configure certain settings at subscription level, then Contributor role at subscription level)

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 12. Azure_SQLDatabase_AuthZ_Use_AAD_Admin

### Display Name
Use AAD Authentication for SQL Database

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAADAuthenticationForSQLServers](Remediate-EnableAADAuthenticationForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 13. Azure_SQLDatabase_DP_Enable_TDE

### Display Name
Transparent data encryption (TDE) must be enabled

### Link to Bulk Remediation Script (BRS)
[Remediate-TransparentDataEncryptionForSQLServers](Remediate-TransparentDataEncryptionForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 14. Azure_Storage_AuthN_Dont_Allow_Anonymous

### Display Name
Ensure secure access to Storage account containers

### Link to Bulk Remediation Script (BRS)
[Remediate-AnonymousAccessOnContainers](Remediate-AnonymousAccessOnContainers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 15. Azure_Storage_DP_Encrypt_In_Transit

### Display Name
Enable Secure transfer to Storage Accounts

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableEncryptionInTransitForStorageAccounts](Remediate-EnableEncryptionInTransitForStorageAccounts.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 16. Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities

### Display Name
Remove external accounts from Azure subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-DontUseNonADIdentities](Remediate-DontUseNonADIdentities.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 17. Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count

### Display Name
Limit access per subscription to 2 or less classic administrators

### Link to Bulk Remediation Script (BRS)
[Remediate-ClassicAdminRoleAssignment](Remediate-ClassicAdminRoleAssignment.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 18. Azure_Subscription_AuthZ_Remove_Deprecated_Accounts

### Display Name
Remove Orphaned accounts from your subscription(s)

### Link to Bulk Remediation Script (BRS)
[Remediate-InvalidAADObjectRoleAssignments](Remediate-InvalidAADObjectRoleAssignments.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## 19. Azure_Subscription_AuthZ_Remove_Management_Certs

### Display Name
Do not use management certificates

### Link to Bulk Remediation Script (BRS)
[Remediate-DoNotUseManagementCertificates](Remediate-DoNotUseManagementCertificates.ps1)

### Minimum permissions required to run the script
ServiceAdministrator/CoAdministrator role

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## 20. Azure_Subscription_Config_ASC_Defender

### Display Name
Enable all Azure Defender plans in Azure Security Center

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigAzureDefender](Remediate-ConfigAzureDefender.ps1)

### Minimum permissions required to run the script
Contributor role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 21. Azure_Subscription_Configure_Conditional_Access_for_PIM

### Display Name
Enable policy to require PIM elevation from SAW for admin roles in Azure subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigureConditionalAccessPolicyForPIM](Remediate-ConfigureConditionalAccessPolicyForPIM.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

___ 


## 22. Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access</br>
### Display Name
Do not grant permanent access for privileged subscription level roles </br>

### Link to Bulk Remediation Script (BRS)
[Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments](Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments/Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## 23. Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG</br>
### Display Name
Do not grant permanent access for privileged roles at resource group level </br>

### Link to Bulk Remediation Script (BRS)
[Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments](Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments/Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## 24. Azure_Subscription_Use_Only_Alt_Credentials
### Display Name
Use Smart-Card ALT (SC-ALT) accounts to access critical roles on subscription and resource groups

### Link to Bulk Remediation Script (BRS)
[Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments](Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments/Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments.ps1)

### Minimum permissions required to run the script
Owner/User Access Administrator role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
No

___ 


## 25. Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port

### Display Name
Reverse proxy port must not be exposed publicly

### Link to Bulk Remediation Script (BRS)
[Remediate-StopExposingServiceFabricReverseProxyPort](Remediate-StopExposingServiceFabricReverseProxyPort.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 26. Azure_AppService_DP_Use_Secure_FTP_Deployment

### Display Name
App Services should use secure FTP deployments

### Link to Bulk Remediation Script (BRS)
[Remediate-SecureFTPDeploymentForAppServices](Remediate-SecureFTPDeploymentForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes


___




































## 26. Azure_FrontDoor_NetSec_Enable_WAF_Configuration 

### Display Name
WAF Policy should be configured on Endpoints in Front Door

### Link to Bulk Remediation Script (BRS)
You can Configure WAF Policy on Front Door using below BRS:  <br/>
[Remediate-ConfigureWAFPolicyForFrontDoor](Remediate-ConfigureWAFPolicyForFrontDoor.ps1) <br/>
You can enable State of WAF Policy configured on Front Door using below BRS:  <br/>
[Remediate-EnableWAFPolicyForFrontDoor](Remediate-EnableWAFPolicyForFrontDoor.ps1) <br/>
You can enable Prevention Mode on WAF Policy configured on Front Door using below BRS:  <br/>
[Remediate-EnableWAFPolicyPreventionModeForFrontDoor](Remediate-EnableWAFPolicyPreventionModeForFrontDoor.ps1) <br/>



### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes


___



## Supports managed identity based remediations
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
