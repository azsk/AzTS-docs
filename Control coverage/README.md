## Security controls covered by Azure Tenant Security (AzTS)

This page displays security controls that are automated via AzTS. Controls table listed under provide following details:
- ControlId and Description
- Dependent Azure API(s) and Properties
- Control spec-let

### Azure Services supported by AzTS

Below resource types can be checked for validating the security controls:

|Feature Name|Resource Type|
|---|---|
|[APIManagement](Feature/APIManagement.md)|Microsoft.ApiManagement/service|
|[ApplicationGateway](Feature/ApplicationGateway.md)|Microsoft.Network/applicationGateways|
|[AppService](Feature/AppService.md)|Microsoft.Web/sites|
|[AutomationAccount](Feature/AutomationAccounts.md)|Microsoft.Automation/automationAccounts|
|[AVDApplicationGroups](Feature/AVDApplicationGroups.md)|Microsoft.DesktopVirtualization/ApplicationGroups|
|[AVDHostPool](Feature/AVDHostPool.md)|Microsoft.DesktopVirtualization/hostpools|
|[AVDWorkspaces](Feature/AVDWorkspaces.md)|Microsoft.DesktopVirtualization/Workspaces|
|[Bastion](Feature/Bastion.md)|Microsoft.Network/bastionHosts|
|[BackupVault] (Feature/BackupVault.md) |Microsoft.DataProtection/backupVaults|
|[BatchAccounts](Feature/BatchAccounts.md)|Microsoft.Batch/batchAccounts|
|[CDN](Feature/CDN.md)|Microsoft.Cdn/profiles|
|[CloudService](Feature/CloudService.md)|Microsoft.ClassicCompute/domainNames|
|[CognitiveSearch](Feature/CognitiveSearch.md)|Microsoft.Search/searchServices|
|[ContainerRegistry](Feature/ContainerRegistry.md)|Microsoft.ContainerRegistry/registries|
|[CosmosDB](Feature/CosmosDB.md)|Microsoft.DocumentDB/databaseAccounts|
|[DataFactory](Feature/DataFactory.md)|Microsoft.DataFactory/factories|
|[DataLakeAnalytics](Feature/DataLakeAnalytics.md)|Microsoft.DataLakeAnalytics/accounts|
|[DataLakeStore](Feature/DataLakeStore.md)|Microsoft.DataLakeStore/accounts|
|[DataShare](Feature/DataShare.md)|Microsoft.DataShare/accounts|
|[DBForMySql](Feature/DBForMySql.md)|Microsoft.DBforMySQL/servers|
|[DBForMySqlFlexibleServer](Feature/DBForMySqlFlexibleServer.md)|Microsoft.DBforMySQL/flexibleServers|
|[DBForPostgreSQL](Feature/DBForPostgreSQL.md)|Microsoft.DBforPostgreSQL/servers|
|[DBForPostgreFlexibleSQL](Feature/DBForPostgreSQLFlexibleServer.md)|Microsoft.Cache/redisEnterprise|
|[EventHub](Feature/EventHub.md)|Microsoft.EventHub/namespaces|
|[FrontDoor](Feature/FrontDoor.md)|Microsoft.Network/frontDoor|
|[HDInsight](Feature/HDInsight.md)|Microsoft.HDInsight/clusters|
|[HybridCompute](Feature/HybridCompute.md)|Microsoft.HybridCompute/machines|
|[IotHubs](Feature/IotHubs.md)|Microsoft.Devices/IotHubs|
|[KeyVault](Feature/KeyVault.md)|Microsoft.KeyVault/vaults|
|[KubernetesService](Feature/KubernetesService.md)|Microsoft.ContainerService/managedClusters|
|[LoadBalancer](Feature/LoadBalancer.md)|Microsoft.Network/loadBalancers |
|[LogicApps](Feature/LogicApps.md)|Microsoft.Logic/workflows|
|[NotificationHub](Feature/NotificationHub.md)|Microsoft.NotificationHubs/namespaces/notificationHubs|
|[MachineLearningWorkspace](Feature/MachineLearningWorkspace.md)|Microsoft.MachineLearningServices/workspaces|
|[NSG](Feature/NSG.md)|Microsoft.Network/networkSecurityGroups|
|[RecoveryServicesVault] (Feature/RecoveryServicesvault.md) |Microsoft.Recoveryservices/vaults|
|[RedisCache](Feature/RedisCache.md)|Microsoft.Cache/Redis|
|[RedisCacheEnterprise](Feature/RedisEnterprise.md)|Microsoft.Cache/redisEnterprise|
|[ServiceBus](Feature/ServiceBus.md)|Microsoft.ServiceBus/namespaces|
|[ServiceFabric](Feature/ServiceFabric.md)|Microsoft.ServiceFabric/clusters|
|[SQLManagedInstance](Feature/SQLManagedInstance.md)|Microsoft.Sql/managedInstances|
|[SQLServer](Feature/SQLServer.md)|Microsoft.Sql/servers|
|[Storage](Feature/Storage.md)|Microsoft.Storage/storageAccounts|
|[StreamAnalyticsJobs](Feature/StreamAnalyticsJobs.md)|Microsoft.StreamAnalytics/streamingJobs|
|[Subscription](Feature/SubscriptionCore.md)|
|[SynapseWorkspace](Feature/SynapseWorkspace.md)|Microsoft.Synapse/workspaces|
|[TrafficManager](Feature/TrafficManager.md)|Microsoft.Network/trafficmanagerprofiles|
|[VirtualMachine](Feature/VirtualMachine.md)|Microsoft.Compute/virtualMachines|
|[VirtualMachineScaleSet](Feature/VirtualMachineScaleSet.md)|Microsoft.Compute/virtualMachineScaleSets|
|[VirtualNetwork](Feature/VirtualNetwork.md)|Microsoft.Network/virtualNetworks|


## Externally Scanned controls in Azure Tenant Security (AzTS)

There are certain controls that cannot be effectively evaluated by AzTS (due to various limitations for e.g. some controls requires VM instances to be in running state) for such controls AzTS will put verification result as 'ExtScanned'. And effective verification result of such controls should be determined based on external feeds later (if available). 

As verification result for such controls depends on other sources and get determined outside AzTS boundary. So, in AzTS UI, controls with verification result 'ExtScanned' are excluded from compliance. By default, such controls will not be listed in scan results view however user can use filter ('AzTS-based controls only') provided in AzTS UI to list these controls.

### List of externally scanned controls

Following controls in AzTS are currently externally scanned:

| ControlId | DisplayName | Description |
|-----------|-------------|-------------|
| Azure_VirtualMachine_SI_Enable_Monitoring_Agent | All VMs must have Monitoring Agent enabled | All VMs must have Monitoring Agent enabled |
| Azure_VirtualMachine_SI_Enable_Vuln_Solution | Install DSRE Qualys Cloud Agent on assets | Vulnerability assessment solution should be installed on VM |
| Azure_VirtualMachine_SI_Missing_OS_Patches | Patch assets to protect against vulnerabilities | Virtual Machine must have all the required OS patches installed |
| Azure_VirtualMachine_SI_Enable_Antimalware | Ensure all devices have anti-malware protection installed and enabled | Antimalware must be enabled with real time protection on Virtual Machine |
| Azure_VirtualMachine_SI_Enable_Sense_Agent | Ensure Sense Agent is installed and healthy | Sense Agent provides Threat and Vulnerability Management (TVM) data and other enhanced telemetry to the backend Microsoft Defender Advanced Threat Protection (MDATP) instance |


## List of controls that depends on Microsoft Defender for Cloud (MDC) in Azure Tenant Security (AzTS)

| ControlId | DisplayName | Description | MDC Recommendation(s) |
|-----------|-------------|-------------|-----------------------|
|Azure_AppService_Config_Disable_Remote_Debugging|Remote debugging should be turned off for Web Applications|Remote debugging must be turned off for App Service|Remote debugging should be turned off for Function App,<br>Remote debugging should be turned off for Web Applications|
| Azure_AppService_DP_Dont_Allow_HTTP_Access | Use HTTPS for app services | App Service must only be accessible over HTTPS | Web Application should only be accessible over HTTPS, <br><br>Function App should only be accessible over HTTPS |
| Azure_AppService_DP_Use_Secure_TLS_Version | Use Approved TLS Version in App Service | Use approved version of TLS for the App Service | TLS should be updated to the latest version for web apps, <br><br>TLS should be updated to the latest version for function apps |
| Azure_AppService_DP_Use_Secure_FTP_Deployment | App Services should use secure FTP deployments | App Services should use secure FTP deployments | FTPS should be required in web apps, <br><br>FTPS should be required in function apps |
| Azure_Storage_AuthN_Dont_Allow_Anonymous | Ensure secure access to storage account containers | The Access Type for containers must not be set to 'Anonymous' | Storage account public access should be disallowed |
| Azure_Storage_DP_Encrypt_In_Transit | Enable Secure transfer to storage accounts | HTTPS protocol must be used for accessing Storage Account resources | Secure transfer to storage accounts should be enabled |
| Azure_VirtualMachine_DP_Enable_Disk_Encryption | Disk encryption should be applied on virtual machines | Disk encryption must be enabled on both OS and data disks for Windows Virtual Machine | Virtual machines should encrypt temp disks, caches, and data flows between Compute and Storage resources |
| Azure_VirtualMachine_SI_MDC_OS_Vulnerabilities | Virtual Machine must be in a healthy state in Microsoft Defender for Cloud |Virtual Machine must be in a healthy state in Microsoft Defender for Cloud | Machines should be configured securely |
| Azure_VirtualMachine_SI_MDC_Recommendations | Virtual Machine must implement all the flagged MDC recommendations | Virtual Machine must implement all the flagged MDC recommendations | Virtual machines should encrypt temp disks, caches, and data flows between Compute and Storage resources, <br><br>Adaptive application controls for defining safe applications should be enabled on your machines, <br><br>Machines should have a vulnerability assessment solution |
| Azure_VirtualMachine_SI_Enable_Vuln_Solution | Install DSRE Qualys Cloud Agent on assets | Vulnerability assessment solution should be installed on VM | Machines should have a vulnerability assessment solution |
| Azure_VirtualMachine_NetSec_Dont_Open_Restricted_Ports | Management ports must not be open on machines | Do not leave restricted ports open on Virtual Machines | Management ports of virtual machines should be protected with just-in-time network access control |
| Azure_VNet_NetSec_Configure_NSG | Associate Subnets with a Network Security Group | NSG should be used for subnets in a virtual network to permit traffic only on required inbound/outbound ports. NSGs should not have a rule to allow any-to-any traffic | Subnets should be associated with a network security group |
| Azure_Subscription_AuthZ_Remove_Deprecated_Accounts | Remove Orphaned accounts from your subscription(s) | Deprecated/stale accounts must not be present on the subscription | Deprecated accounts should be removed from subscriptions |
|Azure_Subscription_Config_MDC_Defender_Plans|Enable all Azure Defender plans in Microsoft Defender for Cloud|Enable all Azure Defender plans in Microsoft Defender for Cloud| Microsoft Defender for DNS should be enabled,<br>Microsoft Defender for Resource Manager should be enabled,<br>Microsoft Defender for Azure SQL Database servers should be enabled,<br>Microsoft Defender for Storage should be enabled,<br>Microsoft Defender for App Service should be enabled,<br>Microsoft Defender for servers should be enabled,<br>Microsoft Defender for SQL servers on machines should be enabled,<br>Microsoft Defender for Key Vault should be enabled,<br>Microsoft Defender for Containers should be enabled
| Azure_RedisCache_DP_Use_SSL_Port | Non-SSL port must not be enabled for Redis Cache | Non-SSL port must not be enabled for Redis Cache | Redis Cache should allow access only via SSL |
| Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel | The ClusterProtectionLevel property must be set to EncryptAndSign for Service Fabric clusters |The ClusterProtectionLevel property must be set to EncryptAndSign for Service Fabric clusters | Service Fabric clusters should have the ClusterProtectionLevel property set to EncryptAndSign |
|Azure_ServiceFabric_AuthN_Client_AuthN_AAD_Only|Use Azure Active directory for client authentication on Service Fabric clusters|Client authentication must be performed only via Azure Active Directory|Service Fabric clusters should only use Azure Active Directory for client authentication|
| Azure_SQLDatabase_AuthZ_Use_AAD_Admin | Use AAD Authentication for SQL Database | Enable Azure AD admin for the SQL Database | SQL servers should have an Azure Active Directory administrator provisioned |
| Azure_SQLDatabase_DP_Enable_TDE | Enable Transparent Data Encryption on SQL databases | Enable Transparent Data Encryption on SQL databases | Transparent Data Encryption on SQL databases should be enabled |

## Frequently Asked Questions (FAQ)

<br>

**Even after remediating my resource, it is still showing as failed against controls in AzTS UI. The controls depends on MDC Assessment. What should I do?**

**NOTE:** *Kindly make sure that the resource(s) is(are) already fixed. The controls which depends on MDC assessment could be found [here](#list-of-controls-that-depends-on-microsoft-defender-for-cloud-mdc-in-azure-tenant-security-azts).* 

If a control depends on MDC assessment(s), validate if resource is in healthy state as per MDC recommendation(s), to validate please follow below mentioned steps:

1. Go to **Azure Portal**.
2. Search for **Microsoft Defender for Cloud** and **open** that.

    ![Image](../Images/MDCEvaluationImage1.png)

3. Click on **Recommendation under the General tab**, in the left side panel.

    ![Image](../Images/MDCEvaluationImage2.png)

4. Click on the **All Recommendations**.
5. Search for the related [recommendations](#list-of-controls-that-depends-on-microsoft-defender-for-cloud-mdc-in-azure-tenant-security-azts) and open it.

    ![Image](../Images/MDCEvaluationImage3.png)

6. Check the list of **unhealthy resources** to see if your resource is present in that list or not.
7. If your resource(s) is not present in unhealthy resources list, run the scan from AzTS UI and check the status of your resource(s).
8. If your resource(s) is present in **unhealthy resources list** and **'Fix' button is available** in the bottom, select the resource(s) that you need to remediate and click on 'Fix' button and wait till your resource(s) show up in **healthy resources list**.

    ![Image](../Images/MDCEvaluationImage4.png)
 
9. If your resource(s) is present in **unhealthy resources list** and **'Fix' button is not available** in the bottom, you have to wait till the MDC evaluation is refreshed and wait till your resource(s) show up in **healthy resources list**. You can find the **refresh interval** at the top. 

    ![Image](../Images/MDCEvaluationImage5.png)

10. Once your resource(s) appear under healthy resources list, run the scan from AzTS UI to check the status of your resource(s).