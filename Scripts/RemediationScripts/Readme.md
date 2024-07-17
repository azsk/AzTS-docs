# Bulk Remediation Script (BRS)

## On this page:

- [Overview](Readme.md#overview)
- [List of controls with Bulk Remediation Script (BRS) support](Readme.md#list-of-controls-with-bulk-remediation-script-brs-support)
- [How to use Bulk Remediation Script (BRS)](Readme.md#how-to-use-bulk-remediation-script-brs)

## **Overview**
Bulk remediation scripts (BRS) can be used to remediate non-compliant resources/subscription for a control. These scripts are limited to the controls that have relatively lower risk to bulk-remediate.

## **List of controls with Bulk Remediation Script (BRS) support**
1. [Azure_APIManagement_AuthN_Use_Microsoft_Entra_ID_for_Client_AuthN](Readme.md#1-Azure_APIManagement_AuthN_Use_Microsoft_Entra_ID_for_Client_AuthN)
2. [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme](Readme.md#2-Azure_APIManagement_DP_Use_HTTPS_URL_Scheme)
3. [Azure_AppService_Config_Disable_Remote_Debugging](Readme.md#3-Azure_AppService_Config_Disable_Remote_Debugging)
4. [Azure_AppService_DP_Dont_Allow_HTTP_Access](Readme.md#4-Azure_AppService_DP_Dont_Allow_HTTP_Access)
5. [Azure_AppService_DP_Use_Secure_TLS_Version](Readme.md#5-Azure_AppService_DP_Use_Secure_TLS_Version)
6. [Azure_CloudService_SI_Disable_RemoteDesktop_Access](Readme.md#6-Azure_CloudService_SI_Disable_RemoteDesktop_Access)
7. [Azure_ContainerRegistry_Config_Enable_Security_Scanning](Readme.md#7-Azure_ContainerRegistry_Config_Enable_Security_Scanning)
8. [Azure_KubernetesService_AuthN_Enabled_Microsoft_Entra_ID](Readme.md#8-Azure_KubernetesService_AuthN_Enabled_Microsoft_Entra_ID)
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
27. [Azure_SQLDatabase_DP_Use_Secure_TLS_Version](Readme.md#27-Azure_SQLDatabase_DP_Use_Secure_TLS_Version)
28. [Azure_Storage_DP_Use_Secure_TLS_Version](Readme.md#28-Azure_Storage_DP_Use_Secure_TLS_Version)
29. [Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration](Readme.md#29-Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration)
30. [Azure_LoadBalancer_NetSec_Restrict_Network_Traffic](Readme.md#30-Azure_LoadBalancer_NetSec_Restrict_Network_Traffic)
31. [Azure_FrontDoor_NetSec_Enable_WAF_Configuration](Readme.md#31-Azure_FrontDoor_NetSec_Enable_WAF_Configuration)
32. [Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration](Readme.md#32-Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration)
33. [Azure_FrontDoor_DP_Use_Secure_TLS_Version](Readme.md#33-Azure_FrontDoor_DP_Use_Secure_TLS_Version)
34. [Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version](Readme.md#34-Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version)
35. [Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version](Readme.md#35-Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version)
36. [Azure_EventHub_DP_Use_Secure_TLS_Version](Readme.md#36-Azure_EventHub_DP_Use_Secure_TLS_Version)
37. [Azure_DBForMySQLFlexibleServer_DP_Enable_SSL](Readme.md#37-Azure_DBForMySQLFlexibleServer_DP_Enable_SSL)
38. [Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version](Readme.md#38-Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version)
39. [Azure_SQLDatabase_AuthZ_Use_Microsoft_Entra_ID_Only](Readme.md#azure_sqldatabase_authz_use_microsoft_entra_id_only)
40. [Azure_AutomationAccounts_DP_Encrypt_Variables](Readme.md#40-Azure_AutomationAccounts_DP_Encrypt_Variables)
41. [Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access](Readme.md#41-Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access)
42. [Azure_KubernetesService_AuthN_Disable_Local_Accounts](Readme.md#42-Azure_KubernetesService_AuthN_Disable_Local_Accounts)
43. [Azure_ServiceBus_DP_Use_Secure_TLS_Version](Readme.md#43-Readme.md#43-Azure_ServiceBus_DP_Use_Secure_TLS_Version)
44. [Azure_RedisCache_DP_Use_Secure_TLS_Version](Readme.md#44-Azure_RedisCache_DP_Use_Secure_TLS_Version)
45. [Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux](Readme.md#45-Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux)
46. [Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux](Readme.md#46-Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux)
47. [Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension](Readme.md#47-Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension)
48. [Azure_Bastion_AuthZ_Disable_Shareable_Link](Readme.md#48-Azure_Bastion_AuthZ_Disable_Shareable_Link)
49. [Azure_AVD_Audit_Enable_HostPool_BootDiagnostics](Readme.md#49-Azure_AVD_Audit_Enable_HostPool_BootDiagnostics)
50. [Azure_AVD_SI_Configure_HostPool_SecureBoot](Readme.md#50-Azure_AVD_SI_Configure_HostPool_SecureBoot)
51. [Azure_CosmosDB_DP_Use_Secure_TLS_Version](Readme.md#51-Azure_CosmosDB_DP_Use_Secure_TLS_Version)
52. [Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_Microsoft_Entra_ID_Only](Readme.md#52-Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_Microsoft_Entra_ID_Only)
53. [Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy](Readme.md#53-azure_virtualmachinescaleset_si_enforce_automatic_upgrade_policy)
54. [Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth](Readme.md#54-azure_appservice_authn_ftp_and_scm_access_disable_basic_auth)
55. [Azure_Subscription_Config_Enable_MicrosoftDefender_Databases](Readme.md#55-Azure_Subscription_Config_Enable_MicrosoftDefender_Databases)
56. [Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager](Readme.md#56-Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager)
57. [Azure_Subscription_Config_Enable_MicrosoftDefender_AppService](Readme.md#57-azure_subscription_config_enable_microsoftdefender_appservice)
58. [Azure_Subscription_Config_Enable_MicrosoftDefender_Storage](Readme.md#58-Azure_Subscription_Config_Enable_MicrosoftDefender_Storage)
59. [Azure_Subscription_Config_Enable_MicrosoftDefender_Container](Readme.md#59-Azure_Subscription_Config_Enable_MicrosoftDefender_Container)
60. [Azure_Subscription_Config_Enable_MicrosoftDefender_Servers](Readme.md#60-Azure_Subscription_Config_Enable_MicrosoftDefender_Servers)
61. [Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault](Readme.md#61-Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault)
62. [Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only](Readme.md#62-azure_aisearch_authz_enable_role_based_api_access_only)
63.  [Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version](Readme.md#63-azure_dbforpostgresqlflexibleserver_dp_use_secure_tls_version)
64. [Azure_DBforPostgreSQL_DP_Use_Secure_TLS_Version](Readme.md#64-azure_dbforpostgresql_dp_use_secure_tls_version)
65. [Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections](Readme.md#65-azure_redisenterprise_dp_use_tls_encrypted_connections)


<br />

___ 


## 1. Azure_APIManagement_AuthN_Use_Microsoft_Entra_ID_for_Client_AuthN

### Display Name
Enterprise applications using APIM must authenticate developers/applications using Microsoft Entra ID (formerly AAD) backed credentials

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


## 8. Azure_KubernetesService_AuthN_Enabled_Microsoft_Entra_ID

### Display Name
Microsoft Entra ID (formerly AAD) should be enabled in Kubernetes Service

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


## 27. Azure_SQLDatabase_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in SQL Server

### Link to Bulk Remediation Script (BRS)
[Remediate-SetSQLServerMinReqTLSVersion](Remediate-SetSQLServerMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes


___

## 28. Azure_Storage_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in Storage Account

### Link to Bulk Remediation Script (BRS)
[Remediate-SetStorageAccountMinReqTLSVersion](Remediate-SetStorageAccountMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___

## 29. Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration

### Display Name
Application Gateway should have Web Application Firewall configured

### Link to Bulk Remediation Script (BRS) for Partially Remediating the control.
[Remediate-NSGConfigurationOnApplicationGatewaySubnet](Remediate-NSGConfigurationOnApplicationGatewaySubnet.ps1)

### Minimum permissions required to run the script
Contributor or Owner role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes


___


## 30. Azure_LoadBalancer_NetSec_Restrict_Network_Traffic

### Display Name
Protect Internet First Applications by restricting traffic on Azure Load Balancer

### Link to Bulk Remediation Script (BRS) 
[Remediate-NSGConfigurationOnLoadBalancerSubnet](Remediate-NSGConfigurationOnLoadBalancerSubnet.ps1)

**Note** : BRS script can be used only to remediate control by configuring network security groups. Remediating with Azure Firewall is not part of this script.

### Minimum permissions required to run the script
Contributor or Owner role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes


___


## 31. Azure_FrontDoor_NetSec_Enable_WAF_Configuration 

### Display Name
WAF Policy should be configured on Endpoints in Front Door.

### Link to Bulk Remediation Script (BRS)
You can Configure WAF Policy on Front Door using below BRS:  <br/>
[Remediate-ConfigureWAFPolicyForFrontDoor](Remediate-ConfigureWAFPolicyForFrontDoor.ps1) <br/>
You can enable State of WAF Policy configured on Front Door using below BRS:  <br/>
[Remediate-EnableWAFPolicyForFrontDoor](Remediate-EnableWAFPolicyForFrontDoor.ps1) <br/>
You can enable Prevention Mode on WAF Policy configured on Front Door using below BRS:  <br/>
[Remediate-EnableWAFPolicyPreventionModeForFrontDoor](Remediate-EnableWAFPolicyPreventionModeForFrontDoor.ps1) <br/>

___


## 32. Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration 

### Display Name
Protect Internet First Applications with Azure FrontDoor and WAF.

### Link to Bulk Remediation Script (BRS)
You can Configure WAF Policy on Front Door using below BRS:  <br/>
[Remediate-ConfigureWAFOnAzureFrontDoorCDN](Remediate-ConfigureWAFOnAzureFrontDoorCDN.ps1) <br/>
You can enable State of WAF Policy configured on Front Door using below BRS:  <br/>
[Remediate-EnableWAFPolicyStateOfAzFrontDoorCDN](Remediate-EnableWAFPolicyStateOfAzFrontDoorCDN.ps1) <br/>
You can enable Prevention Mode on WAF Policy configured on Front Door using below BRS:  <br/>
[Remediate-SetWAFPolicyModeToPreventionForAzFrontDoorCDN](Remediate-SetWAFPolicyModeToPreventionForAzFrontDoorCDN.ps1) <br/>

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation?
Yes

### Supports rollback?
Yes


___
## 33. Azure_FrontDoor_DP_Use_Secure_TLS_Version

### Display Name
Front Door Classic should have Approved Minimum TLS version

### Link to Bulk Remediation Script (BRS)
[Remediate-SetClassicFrontDoorMinTLSVersion](Remediate-SetClassicFrontDoorMinTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

---

## 34. Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version

### Display Name
Front Door should have Approved Minimum TLS version.

### Link to Bulk Remediation Script (BRS)
[Remediate-CdnFrontDoorMinTLSVersion](Remediate-CdnFrontDoorMinTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___
## 35. Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure SQL Managed Instance

### Link to Bulk Remediation Script (BRS)
[Remediate-SetSQLManagedInstanceMinReqTLSVersion](Remediate-SetSQLManagedInstanceMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___

## 36. Azure_EventHub_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Event Hub Namespace.

### Link to Bulk Remediation Script (BRS)
[Remediate-SetEventHubNamespaceMinTLSVersion](Remediate-SetEventHubNamespaceMinTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor or Owner role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___
## 37. Azure_DBForMySQLFlexibleServer_DP_Enable_SSL

### Display Name
SSL must be enabled for Azure database for MySQL flexible server


### Link to Bulk Remediation Script (BRS)
[Remediate-EnableSSLDBForMySQLFlexibleServer](Remediate-EnableSSLDBForMySQLFlexibleServer.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___

## 38. Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Database for MySQL - Flexible Servers.

### Link to Bulk Remediation Script (BRS)
[Remediate-SetDBForMySQLFlexibleServerMinReqTLSVersion](Remediate-SetDBForMySQLFlexibleServerMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___

## 39. Azure_SQLDatabase_AuthZ_Use_Microsoft_Entra_ID_Only

### Display Name
Enable Entra ID (formerly AAD) as only Authentication for the SQL Server

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAADOnlyAuthenticationForSQLServers](./Remediate-EnableAADOnlyAuthenticationForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Restricted to 'User' account type

### Supports rollback?
Yes

### User Inputs Required?
Yes 

To set Entra ID (formerly AAD) Only Authentication on SQL Server, Entra ID (formerly AAD) Admin should be configured. 

Enable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

After running the above command a remediation file is generated where the user input is expected if applicable.

If the SQL Server being remediated is having AAD Admin configured already, no input is required, Email Id value for the respective SQL Server in the remediation file shows NA(as AAD Admin is already configured), otherwise user is expected to fill in the Email Id (ex: abc@microsoft.com) in the blank cells of Email Id column (indicates AAD Admin has not been already set for the respective SQL Servers).
___

## 40. Azure_AutomationAccounts_DP_Encrypt_Variables

### Display Name
Automation account variables must be encrypted

### Link to Bulk Remediation Script (BRS)
[Remediate-EncryptAutomationAccountVariables](Remediate-EncryptAutomationAccountVariables.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
No

___

## 41. Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access

### Display Name
Public network access on Azure SQL Database should be disabled

### Link to Bulk Remediation Script (BRS)
[Remediate-DisablePublicNetworkAccessOnSqlServer](Remediate-DisablePublicNetworkAccessOnSqlServer.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___

## 42. Azure_KubernetesService_AuthN_Disable_Local_Accounts

### Display Name
Local accounts should be disabled in Kubernetes Service

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableLocalAccountsForKubernetesService](Remediate-DisableLocalAccountsForKubernetesService.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
No

___ 

## 43. Azure_ServiceBus_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Service Bus

### Link to Bulk Remediation Script (BRS)
[Remediate-SetServiceBusMinReqTLSVersion.ps1](Remediate-SetServiceBusMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 

## 44. Azure_RedisCache_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure RedisCache.

### Link to Bulk Remediation Script (BRS)
[Remediate-SetRedisCacheMinReqTLSVersion](Remediate-SetRedisCacheMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 

## 45. Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux

### Display Name
Entra ID (formerly AAD) extension must be deployed to the Linux VM.

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigureAADAuthExtOnLinuxVM](Remediate-ConfigureAADAuthExtOnLinuxVM.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 46. Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux

### Display Name
Entra ID (formerly AAD) extension must be deployed to the Linux VMSS

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigureAADAuthExtOnLinuxVMSS](Remediate-ConfigureAADAuthExtOnLinuxVMSS.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 

## 47. Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension

### Display Name
Guest Configuration extension must be deployed to the VM using Azure Policy assignment.

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigureGuestExtAndSystemAssignedMIForVM](Remediate-ConfigureGuestExtAndSystemAssignedMIForVM.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes
___ 

## 48. Azure_Bastion_AuthZ_Disable_Shareable_Link

### Display Name
Azure Bastion Shareable links must not be used

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableBastionShareableLink](Remediate-DisableBastionShareableLink.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 49. Azure_AVD_Audit_Enable_HostPool_BootDiagnostics

### Display Name
Boot Diagnostic must be enabled with Managed Storage Account on Azure AVD Host pool VMs.

### Link to Bulk Remediation Script (BRS)
[Remediate-BootDiagnosticsForAVDHostPool](Remediate-BootDiagnosticsforAVDHostPool.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 50. Azure_AVD_SI_Configure_HostPool_SecureBoot

### Display Name
Azure AVD Host pool VMs should be of security type Trusted launch with Secure boot and vTPM enabled.

### Link to Bulk Remediation Script (BRS)
[Remediate-TrustedLaunchForAVDHostPool](Remediate-TrustedLaunchforAVDHostPool.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 


## 51. 	Azure_CosmosDB_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for the Cosmos DB

### Link to Bulk Remediation Script (BRS)
[Remediate-SetCosmosDBAccountMinReqTLSVersion](Remediate-SetCosmosDBAccountMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

___ 

## 52. Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_Microsoft_Entra_ID_Only

### Display Name
Synapse workspace SQL pools must have only Entra ID based authentication enabled.

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableEntraIdAuthenticationOnlyForSynapseWorkspace](Remediate-EnableEntraIdAuthenticationOnlyForSynapseWorkspace.ps1)


### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

---

## 53. 	Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy

### Display Name
Enforce Automatic Upgrade policy in VMSS

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigureUpgradePolicyModeForVMSS](Remediate-ConfigureUpgradePolicyModeForVMSS.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Partial

---

## 54. 	Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth

### Display Name
 AppService must not use basic authentication for FTP and SCM access.

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableBasicAuthForAppServices](Remediate-DisableBasicAuthForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

---

## 55. Azure_Subscription_Config_Enable_MicrosoftDefender_Databases

### Display Name
Microsoft Defender for Databases should be enabled on subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAzureDefender](Remediate-EnableMicrosoftDefenders.ps1)

### Minimum permissions required to run the script
Owner/Security Admin role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
No

### Supports rollback?
Yes

---

## 56. Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager

### Display Name
Microsoft Defender for Resource Manager should be enabled on subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAzureDefender](Remediate-EnableMicrosoftDefenders.ps1)

### Minimum permissions required to run the script
Owner/Security Admin role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
No

### Supports rollback?
Yes

---

## 57. Azure_Subscription_Config_Enable_MicrosoftDefender_AppService

### Display Name
Microsoft Defender for App Service should be enabled on subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAzureDefender](Remediate-EnableMicrosoftDefenders.ps1)

### Minimum permissions required to run the script
Owner/Security Admin role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
No

### Supports rollback?
Yes

---

## 58. Azure_Subscription_Config_Enable_MicrosoftDefender_Storage

### Display Name
Microsoft Defender for Storage should be enabled on subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAzureDefender](Remediate-EnableMicrosoftDefenders.ps1)

### Minimum permissions required to run the script
Owner/Security Admin role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
No

### Supports rollback?
Yes

---

## 59. Azure_Subscription_Config_Enable_MicrosoftDefender_Container

### Display Name
Microsoft Defender for Containers should be enabled on subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAzureDefender](Remediate-EnableMicrosoftDefenders.ps1)

### Minimum permissions required to run the script
Owner/Security Admin role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
No

### Supports rollback?
Yes

---

## 60. Azure_Subscription_Config_Enable_MicrosoftDefender_Servers

### Display Name
Microsoft Defender for Servers should be enabled on subscriptions

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAzureDefender](Remediate-EnableMicrosoftDefenders.ps1)

### Minimum permissions required to run the script
Owner/Security Admin role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
No

### Supports rollback?
Yes


---

## 61. Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault

### Display Name
 Microsoft Defender for Key Vault should be enabled on subscriptions.

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAzureDefender](Remediate-EnableMicrosoftDefenders.ps1)

### Minimum permissions required to run the script
Owner/Security Admin role at subscription level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
No

### Supports rollback?
Yes

---

## 62. Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only

### Display Name
 Protect Azure AI Search Instances by only allowing RBAC API Access

### Link to Bulk Remediation Script (BRS)
[Remediate-ConfigureRoleBasedAPIAcessOnlyForAISearch](Remediate-ConfigureRoleBasedAPIAcessOnlyForAISearch.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes


---

## 63. Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Database for PostgreSQL - Flexible Servers

### Link to Bulk Remediation Script (BRS)
[Remediate-SetDBForPostgreSQLFlexibleServerMinReqTLSVersion](Remediate-SetDBForPostgreSQLFlexibleServerMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

---

## 64. Azure_DBforPostgreSQL_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Database for PostgreSQL - Single Servers

### Link to Bulk Remediation Script (BRS)
[Remediate-SetDBForPostgreSQLSingleServerMinReqTLSVersion](Remediate-SetDBForPostgreSQLSingleServerMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

### [Supports managed identity](Readme.md#supports-managed-identity-based-remediations) based remediation
Yes

### Supports rollback?
Yes

---

## 65. Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections

### Display Name
Use approved version of TLS and enable secure client protocol for Redis Enterprise

### Link to Bulk Remediation Script (BRS)
[Remediate-SetRedisEnterpriseTLSEncryptedConnections](Remediate-SetRedisEnterpriseTLSEncryptedConnections.ps1)

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