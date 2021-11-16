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
|[AppService](Feature/AppService.md)|Microsoft.Web/sites|
|[CDN](Feature/CDN.md)|Microsoft.Cdn/profiles|
|[CloudService](Feature/CloudService.md)|Microsoft.ClassicCompute/domainNames|
|[ContainerRegistry](Feature/ContainerRegistry.md)|Microsoft.ContainerRegistry/registries|
|[CosmosDB](Feature/CosmosDB.md)|Microsoft.DocumentDB/databaseAccounts|
|[DataLakeAnalytics](Feature/DataLakeAnalytics.md)|Microsoft.DataLakeAnalytics/accounts|
|[DataLakeStore](Feature/DataLakeStore.md)|Microsoft.DataLakeStore/accounts|
|[DBForMySql](Feature/DBForMySql.md)|Microsoft.DBforMySQL/servers|
|[DBForPostgreSQL](Feature/DBForPostgreSQL.md)|Microsoft.DBforPostgreSQL/servers|
|[EventHub](Feature/EventHub.md)|Microsoft.EventHub/namespaces|
|[HDInsight](Feature/HDInsight.md)|Microsoft.HDInsight/clusters|
|[KubernetesService](Feature/KubernetesService.md)|Microsoft.ContainerService/managedClusters|
|[RedisCache](Feature/RedisCache.md)|Microsoft.Cache/Redis|
|[ServiceBus](Feature/ServiceBus.md)|Microsoft.ServiceBus/namespaces|
|[ServiceFabric](Feature/ServiceFabric.md)|Microsoft.ServiceFabric/clusters|
|[SQLManagedInstance](Feature/SQLManagedInstance.md)|Microsoft.Sql/managedInstances|
|[SQLServer](Feature/SQLServer.md)|Microsoft.Sql/servers|
|[Storage](Feature/Storage.md)|Microsoft.Storage/storageAccounts|
|[Subscription](Feature/SubscriptionCore.md)|
|[TrafficManager](Feature/TrafficManager.md)|Microsoft.Network/trafficmanagerprofiles|
|[VirtualMachine](Feature/VirtualMachine.md)|Microsoft.Compute/virtualMachines|
|[VirtualMachineScaleSet](Feature/VirtualMachineScaleSet.md)|Microsoft.Compute/virtualMachineScaleSets|
|[VirtualNetwork](Feature/VirtualNetwork.md)|Microsoft.Network/virtualNetworks|

## Externally Scanned controls in Azure Tenant Security (AzTS)

There are certain controls that can not be effectively evaluated by AzTS (due to various limitations for e.g. some controls requires VM instances to be in running state) for such controls AzTS will put verification result as 'ExtScanned'. And effective verification result of such controls should be determined based on external feeds later (if available). 

As verification result for such controls depends on other sources and get determined outside AzTS boundary. So, in AzTS UI, controls with verification result 'ExtScanned' are excluded from compliance. By default such controls will not be listed in scan results view however user can use filter ('AzTS-based controls only') provided in AzTS UI to list these controls.

### List of externally scanned controls

Following controls in AzTS are currently externally scanned:

| ControlId | DisplayName | Description |
|-----------|-------------|-------------|
| Azure_VirtualMachine_SI_Enable_Monitoring_Agent|All VMs must have Monitoring Agent enabled|All VMs must have Monitoring Agent enabled|
| Azure_VirtualMachine_SI_Enable_Vuln_Solution|Install DSRE Qualys Cloud Agent on assets|Vulnerability assessment solution should be installed on VM|
| Azure_VirtualMachine_SI_Missing_OS_Patches|Patch assets to protect against vulnerabilities|Virtual Machine must have all the required OS patches installed|
| Azure_VirtualMachine_SI_Enable_Antimalware|Ensure all devices have anti-malware protection installed and enabled|Antimalware must be enabled with real time protection on Virtual Machine|
| Azure_VirtualMachine_SI_Enable_Sense_Agent|Ensure Sense Agent is installed and healthy|Sense Agent provides Threat and Vulnerability Management (TVM) data and other enhanced telemetry to the backend Microsoft Defender Advanced Threat Protection (MDATP) instance|
