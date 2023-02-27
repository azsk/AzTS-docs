## **List of controls supported for remediation through AzTS UI**
***

1. [Azure_Storage_AuthN_Dont_Allow_Anonymous](ControlsEligibleForRemediationThroughUI.md#1-Azure_Storage_AuthN_Dont_Allow_Anonymous)

2. [Azure_Storage_DP_Encrypt_In_Transit](ControlsEligibleForRemediationThroughUI.md#2-Azure_Storage_DP_Encrypt_In_Transit)

3. [Azure_AppService_Config_Disable_Remote_Debugging](ControlsEligibleForRemediationThroughUI.md#3-Azure_AppService_Config_Disable_Remote_Debugging)

4. [Azure_AppService_DP_Dont_Allow_HTTP_Access](ControlsEligibleForRemediationThroughUI.md#4-Azure_AppService_DP_Dont_Allow_HTTP_Access)

5. [Azure_AppService_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#5-Azure_AppService_DP_Use_Secure_TLS_Version)

6. [Azure_ContainerRegistry_Config_Enable_Security_Scanning](ControlsEligibleForRemediationThroughUI.md#6-Azure_ContainerRegistry_Config_Enable_Security_Scanning)

7. [Azure_KubernetesService_AuthN_Enabled_AAD](ControlsEligibleForRemediationThroughUI.md#7-Azure_KubernetesService_AuthN_Enabled_AAD)

8. [Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN](ControlsEligibleForRemediationThroughUI.md-Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN)

9. [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme](ControlsEligibleForRemediationThroughUI.md-Azure_APIManagement_DP_Use_HTTPS_URL_Scheme)

10. [Azure_SQLDatabase_DP_Enable_TDE](ControlsEligibleForRemediationThroughUI.md-Azure_SQLDatabase_DP_Enable_TDE)

11. [Azure_CloudService_SI_Disable_RemoteDesktop_Access](ControlsEligibleForRemediationThroughUI.md-Azure_CloudService_SI_Disable_RemoteDesktop_Access)

12. [Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel](ControlsEligibleForRemediationThroughUI.md#1-Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel)

13. [Azure_ServiceBus_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#13-azure_servicebus_dp_use_secure_tls_version)

14. [Azure_SQLDatabase_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#14-Azure_SQLDatabase_DP_Use_Secure_TLS_Version)

15. [Azure_Storage_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#15-Azure_Storage_DP_Use_Secure_TLS_Version)

16. [Azure_Storage_AuthZ_Set_SAS_Expiry_Interval](ControlsEligibleForRemediationThroughUI.md#16-Azure_Storage_AuthZ_Set_SAS_Expiry_Interval)

17. [Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#17-azure_sqlmanagedinstance_dp_use_secure_tls_version)

18. [Azure_EventHub_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#18-Azure_EventHub_DP_Use_Secure_TLS_Version)

19. [Azure_DBForMySQLFlexibleServer_DP_Enable_SSL](ControlsEligibleForRemediationThroughUI.md#19-Azure_DBForMySQLFlexibleServer_DP_Enable_SSL)

20. [Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#20-Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version)

21. [Azure_AutomationAccounts_DP_Encrypt_Variables](ControlsEligibleForRemediationThroughUI.md#21-Azure_AutomationAccounts_DP_Encrypt_Variables)

22. [Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access](ControlsEligibleForRemediationThroughUI.md#22-Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access)



<br />
___

## 1. Azure_Storage_AuthN_Dont_Allow_Anonymous

### Display Name
Ensure secure access to Storage account containers

### Link to Bulk Remediation Script (BRS)
[Remediate-AnonymousAccessOnContainers](Remediate-AnonymousAccessOnContainers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 2. Azure_Storage_DP_Encrypt_In_Transit

### Display Name
Enable Secure transfer to Storage Accounts

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableEncryptionInTransitForStorageAccounts](Remediate-EnableEncryptionInTransitForStorageAccounts.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 3. Azure_AppService_Config_Disable_Remote_Debugging

### Display Name
Remote debugging should be turned off for Web Applications

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableRemoteDebuggingForAppServices](Remediate-DisableRemoteDebuggingForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 4. Azure_AppService_DP_Dont_Allow_HTTP_Access

### Display Name
Use HTTPS for App Services

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableHTTPSForAppServices](Remediate-EnableHTTPSForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 5. Azure_AppService_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in App Service

### Link to Bulk Remediation Script (BRS)
[Remediate-SetAppServiceMinReqTLSVersion](Remediate-SetAppServiceMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 6. Azure_ContainerRegistry_Config_Enable_Security_Scanning

### Display Name
Security scanner identity must be granted access to Container Registry for image scans

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableSecurityScanningForContainerRegistry](Remediate-EnableSecurityScanningForContainerRegistry.ps1)

### Minimum permissions required to run the script
Reader role at subscription level and Contributor role at resource level

___

## 7. Azure_KubernetesService_AuthN_Enabled_AAD

### Display Name
AAD should be enabled in Kubernetes Service

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAADForKubernetesService](Remediate-EnableAADForKubernetesService.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 8. Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN

### Display Name
Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials

### Link to Bulk Remediation Script (BRS)
[Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices](Remediate-DeleteNonAADIdentityProvidersInAPIManagementServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 9. Azure_APIManagement_DP_Use_HTTPS_URL_Scheme

### Display Name
Ensure API Management service is accessible only over HTTPS

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableHTTPSForAPIsInAPIManagementServices](Remediate-EnableHTTPSForAPIsInAPIManagementServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 10. Azure_SQLDatabase_DP_Enable_TDE

### Display Name
Transparent data encryption (TDE) must be enabled

### Link to Bulk Remediation Script (BRS)
[Remediate-TransparentDataEncryptionForSQLServers](Remediate-TransparentDataEncryptionForSQLServers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 11. Azure_CloudService_SI_Disable_RemoteDesktop_Access

### Display Name
Remote Desktop (RDP) access must be disabled on cloud service roles

### Link to Bulk Remediation Script (BRS)
[Remediate-RemoteDesktopAccess](Remediate-RemoteDesktopAccess.ps1)

### Minimum permissions required to run the script
Classic Role Assignment at subscription level

___

## 12. Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel

### Display Name
Cluster Protection Level must be EncryptandSign

### Link to Bulk Remediation Script (BRS)
[Remediate-SetClusterProtectionLevelForServiceFabric](Remediate-SetClusterProtectionLevelForServiceFabric.ps1)

### Minimum permissions required to run the script
Owner or higher priviliged role on the Service Fabric(s)

___

## 13. Azure_ServiceBus_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Service Bus

### Link to Bulk Remediation Script (BRS)
[Remediate-SetServiceBusMinReqTLSVersion](./Remediate-SetServiceBusMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Azure Data Owner role on Service Bus Namespace

___

## 14. Azure_SQLDatabase_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in SQL Server

### Link to Bulk Remediation Script (BRS)
[Remediate-SetSQLServerMinReqTLSVersion](Remediate-SetSQLServerMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 15. Azure_Storage_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in Storage Account

### Link to Bulk Remediation Script (BRS)
[Remediate-SetStorageAccountRequiredTLSVersion](Remediate-SetStorageAccountMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Owner or higher priviliged role on the Storage Account(s)

___

## 16. Azure_Storage_AuthZ_Set_SAS_Expiry_Interval

### Display Name
Shared Access Signature (SAS) expiry interval must be less than approved upper limit for Azure Storage

### Link to Bulk Remediation Script (BRS)
[Remediate-SASExpiryIntervalForStorageAccounts](Remediate-SASExpiryIntervalForStorageAccounts.ps1)

### Minimum permissions required to run the script
Contributor or higher privileged role on the Storage Account(s)

___


## 17. Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure SQL Managed Instance

### Link to Bulk Remediation Script (BRS)
[Remediate-SetSQLManagedInstanceMinReqTLSVersion](Remediate-SetSQLManagedInstanceMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor or higher privileged role on the Managed Instance(s)

___


## 18. Azure_EventHub_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Event Hub Namespace.

### Link to Bulk Remediation Script (BRS)
[Remediate-SetEventHubNamespaceMinTLSVersion](Remediate-SetEventHubNamespaceMinTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor or higher privileged role on the Event Hub Namespace(s)

___


## 19. Azure_DBForMySQLFlexibleServer_DP_Enable_SSL

### Display Name
SSL must be enabled for Azure database for MySQL flexible server

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableSSLDBForMySQLFlexibleServer](Remediate-EnableSSLDBForMySQLFlexibleServer.ps1)

### Minimum permissions required to run the script
Contributor or higher privileged role on the Azure database for MYSQL flexible server

___


## 20. Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Database for MySQL - Flexible Servers.

### Link to Bulk Remediation Script (BRS)
[Remediate-SetDBForMySQLFlexibleServerMinReqTLSVersion](Remediate-SetDBForMySQLFlexibleServerMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor or higher privileged role on the Storage Account(s)

___


## 21. Azure_AutomationAccounts_DP_Encrypt_Variables

### Display Name
Automation account variables must be encrypted

### Link to Bulk Remediation Script (BRS)
[Remediate-EncryptAutomationAccountVariables](Remediate-EncryptAutomationAccountVariables.ps1)

### Minimum permissions required to run the script
Contributor or higher privileged role on the Automation Account(s)

___
## 22. Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access

### Display Name
Public network access on Azure SQL Database should be disabled

### Link to Bulk Remediation Script (BRS)
[Remediate-DisablePublicNetworkAccessOnSqlServer](Remediate-DisablePublicNetworkAccessOnSqlServer.ps1)

### Minimum permissions required to run the script
Contributor or higher privileged role on the Automation Account(s)

___