# KubernetesService

**Resource Type:** Microsoft.ContainerService/managedClusters

<!-- TOC -->

- [Azure_KubernetesService_Deploy_Enable_Cluster_RBAC](#azure_kubernetesservice_deploy_enable_cluster_rbac)
- [Azure_KubernetesService_AuthN_Enabled_AAD](#azure_kubernetesservice_authn_enabled_aad)
- [Azure_KubernetesService_Deploy_Use_Latest_Version](#azure_kubernetesservice_deploy_use_latest_version)
- [Azure_KubernetesService_Audit_Enable_Monitoring](#azure_kubernetesservice_audit_enable_monitoring)
- [Azure_KubernetesService_NetSec_Dont_Open_Management_Ports](#azure_kubernetesservice_netsec_dont_open_management_ports)
- [Azure_KubernetesService_Audit_Enable_Diagnostics_Log](#azure_kubernetesservice_audit_enable_diagnostics_log)
- [Azure_KubernetesService_DP_Disable_HTTP_Application_Routing](#azure_kubernetesservice_dp_disable_http_application_routing)

<!-- /TOC -->
<br/>

___ 

## Azure_KubernetesService_Deploy_Enable_Cluster_RBAC 

### Display Name 
Cluster RBAC must be enabled in Kubernetes Service 

### Rationale 
Enabling RBAC in a cluster lets you finely control access to various operations at the cluster/node/pod/namespace scopes for different stakeholders. Without RBAC enabled, every user has full access to the cluster which is a violation of the principle of least privilege. Note that Azure Kubernetes Service does not currently support other mechanisms to define authorization in Kubernetes (such as Attribute-based Access Control authorization or Node authorization). 

### Control Spec 

> **Passed:** 
> RBAC is enabled for AKS.
> 
> **Failed:** 
> RBAC is disabled for AKS.
> 
### Recommendation 

- **Azure Portal** 

	 RBAC flag must be enabled while creating the Kubernetes Service. Existing non-RBAC enabled Kubernetes Service clusters cannot currently be updated for RBAC use. Refer: https://docs.microsoft.com/en-us/azure/aks/concepts-identity#kubernetes-role-based-access-control-rbac. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Container Services at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=2020-09-01<br />
**Properties:** properties.enableRBAC
 <br />

<br />

___ 

## Azure_KubernetesService_AuthN_Enabled_AAD 

### Display Name 
AAD should be enabled in Kubernetes Service 

### Rationale 
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions. 

### Control Spec 

> **Passed:** 
> Azure AD applications (Server App and Client App) are configured for Kubernetes Service for authentication of the credentials provided by the client.
> 
> **Failed:** 
> Azure AD applications (Server App and Client App) are not configured for Kubernetes Service for authentication of the credentials provided by the client.
> 
### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/aks/aad-integration to configure AAD in Kubernetes Service. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Container Services at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=2020-09-01<br />
**Properties:** properties.clientAppID, properties.serverAppID, properties.tenantID, properties.managed
 <br />

<br />

___ 

## Azure_KubernetesService_Deploy_Use_Latest_Version 

### Display Name 
[Preview]: Kubernetes Services should be upgraded to a non-vulnerable Kubernetes version 

### Rationale 
Running on older versions could mean you are not using latest security classes. Usage of such old classes and types can make your application vulnerable. 

### Control Settings 
```json 
{
    "kubernetesVersion": "1.14.8,1.15.10,1.16.7"
}
 ```

### Control Spec 

> **Passed:** 
> AKS is running on one of the defined versions.
> 
> **Failed:** 
> AKS is not running on the required Kubernetes version.
> 
### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/aks/upgrade-cluster. 
<!-- 
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Container Services at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=2020-09-01<br />
**Properties:** properties.kubernetesVersion
 <br />

<br />

___ 

## Azure_KubernetesService_Audit_Enable_Monitoring 

### Display Name 
Monitoring must be enabled for Azure Kubernetes Service 

### Rationale 
Auditing enables log collection of important system events pertinent to security. Regular monitoring of audit logs can help to detect any suspicious and malicious activity early and respond in a timely manner. 

### Control Spec 

> **Passed:** 
> Kubernetes resource have LA configured and monitoring is enabled.
> 
> **Failed:** 
> Kubernetes resource do not have LA configured and monitoring is disabled.
> 
### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-overview. 
<!-- 
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Container Services at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=2020-09-01<br />
**Properties:** properties.addonProfiles.omsagent
 <br />

<br />

___ 

## Azure_KubernetesService_NetSec_Dont_Open_Management_Ports 

### Display Name 
Do not leave management ports open on Kubernetes nodes 

### Rationale 
Open remote management ports expose a VM/compute node to a high level of risk from internet-based attacks that attempt to brute force credentials to gain admin access to the machine. 

### Control Settings 
```json 
{
    "RestrictedPorts": "445,3389,5985,22"
}
 ``` 

### Control Spec 

> **Passed:** 
> If NSG is configured and no inbound port is open or if restricted ports not found.
> 
> **Failed:** 
> If NSG is not configured or if restricted ports found.
> 
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> VM Settings --> Networking --> Inbound security rules --> Select security rule which allows management ports (e.g. RDP-3389, WINRM-5985, SSH-22, SMB-445) --> Click 'Deny' under Action --> Click Save. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Network Interfaces at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01<br />
**Properties:** properties.ipConfigurations, properties.networksecuritygroup
 <br />

- ARM API to list Network Security Groups at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01<br />
**Properties:** properties.destinationAddressPrefixes
 <br /> 

- ARM API to list Virtual Networks at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01<br />
**Properties:** properties.subnets
 <br />

<br />

___ 

## Azure_KubernetesService_Audit_Enable_Diagnostics_Log 

### Display Name 
Diagnostics logs must be enabled for Kubernetes service 

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well. 

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "kube-apiserver",
        "kube-audit",
        "kube-audit-admin",
        "Guard"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
 ``` 

### Control Spec 

> **Passed:** 
> 1. Required diagnostic logs are enabled.
>
>       and
>
> 2. At least one of the below setting configured:
> a. Log Analytics.
> b. Storage account (with min Retention period of 365 or forever(Retention period 0).
> c. Event Hub.
> 
> **Failed:** 
> 1. Diagnostics setting is disabled for resource.
>
>       or
>
> 2. Diagnostic settings meet the following conditions:
> a. All diagnostic logs are not enabled.
> b. None of the below setting is configured:
> i. Log Analytics.
> ii. Storage account (with min Retention period of 365 or forever(Retention period 0).
> iii. Event Hub.
> 
> **Error:** 
> Required logs are not configured in control settings.
> 
### Recommendation 

- **Azure Portal** 

	 You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list diagnostic setting details of Kubernetes service resources: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Kubernetes/connectedClusters/{serviceName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:**<br /> name, <br />
properties.logs.category, <br />
properties.logs.enabled, <br />
properties.logs.retentionPolicy.enabled, <br />
properties.logs.retentionPolicy.days, <br />
properties.workspaceId, <br />
properties.storageAccountId, <br />
properties.eventHubName
 <br />

<br />

___ 

## Azure_KubernetesService_DP_Disable_HTTP_Application_Routing 

### Display Name 
HTTP application routing should be disabled in Kubernetes Service 

### Rationale 
Enabling HTTP application routing creates publicly accessible DNS names for application endpoints which makes applications deployed to your cluster vulnerable to various network attacks. 

### Control Spec 

> **Passed:** 
> HTTP app routing is disabled for Kubernetes resource.
> 
> **Failed:** 
> HTTP app routing is enabled for Kubernetes resource.
> 
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> your Kubernetes Service --> Settings --> Networking --> Network options --> 'Enable HTTP application routing' option --> Uncheck checkbox. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Container Services at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=2020-09-01<br />
**Properties:** properties.addonProfiles.httpApplicationRouting.enabled
 <br />

<br />

___ 

