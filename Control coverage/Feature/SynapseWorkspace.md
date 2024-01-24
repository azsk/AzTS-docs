# SynapseWorkspace

**Resource Type:** Microsoft.Synapse/workspaces

<!-- TOC -->

- [Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_Microsoft_Entra_ID_Only](#azure_synapseworkspace_authn_sql_pools_use_microsoft_entra_id_only)
- [Azure_SynapseWorkspace_Audit_Enable_Diagnostics_Log](#azure_synapseworkspace_audit_enable_diagnostics_log)
- [Azure_Synapse_NetSec_Dont_Allow_Universal_IP_Range](#azure_synapse_netsec_dont_allow_universal_ip_range)

<!-- /TOC -->
<br/>

___ 

## Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_Microsoft_Entra_ID_Only 

### Display Name 
Synapse workspace SQL pools must have only Microsoft Entra ID based authentication enabled

### Rationale 
The built in SQL pool of the Synapse workspace creates an admin login and password by default, but it can be restricted to AAD auth only. This is helpful to mitigate any brute force attacks or misconfigs across environments that can compromise the password and get access to the SQL pool.


### Control Spec 

> **Passed:** 
> Microsoft Entra ID authentication only is enabled.
> 
> **Failed:** 
> Microsoft Entra ID authentication only is not enabled.

> 
### Recommendation 

- **Azure Portal** 
 1. Navigate to the Synapse resource in Azure Portal. 
 2. Go to 'Microsoft Entra ID' under the settings tab. 
 3. Check the property 'Support only Microsoft Entra ID authentication for this workspace'. Make sure an Microsoft Entra admin is set. 
 Refer to: https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/active-directory-authentication#disable-local-authentication
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list Synapse workspaces at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Synapse/workspaces?api-version=2021-06-01<br />
**Properties:**  properties.azureADOnlyAuthentication
 <br />

___ 



## Azure_SynapseWorkspace_Audit_Enable_Diagnostics_Log 

### Display Name 
Diagnostic settings must be enabled for Synapse workspace

### Rationale 
Diagnostic logs are needed for creating activity trail while investigating an incident or a compromise.

### Control Settings 
```json 
{
"DiagnosticForeverRetentionValue": "0",
"DiagnosticMinRetentionPeriod": "90",
"DiagnosticLogs": [
  "SynapseRbacOperations",
  "GatewayApiRequests",
  "SQLSecurityAuditEvents",
  "BuiltinSqlReqsEnded",
  "IntegrationPipelineRuns",
  "IntegrationActivityRuns",
  "IntegrationTriggerRuns",
  "SynapseLinkEvent"
]
}
```

### Control Spec 

> **Passed:**
> 1. Required diagnostic logs are enabled.
> 2. At least one of the below settings configured:
> a. Log Analytics.
> b. Storage account with min Retention period of 90 or forever(Retention period 0).
> c. Event Hub.
>
> **Failed:**
> 1. Diagnostics setting is disabled for resource.
> 
>       or
>
> 2. Diagnostic settings meet the following conditions:
> a. All diagnostic logs are not enabled.
> b. None of the below settings is configured:
> i. Log Analytics.
> ii. Storage account with min Retention period of 90 or forever(Retention period 0).
> iii. Event Hub.
> 



### Recommendation 

- **Azure Portal** 
 Create or update the diagnostic settings from the Azure Portal by following the steps given [here](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings?tabs=portal#create-diagnostic-settings)

### Azure Policies or REST APIs used for evaluation 

- REST API to list diagnostic setting details of Synapse workspace resources: {resourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview <br />
**Properties:**
name<br />
properties.logs.category<br />
properties.logs.enabled<br />
properties.logs.retentionPolicy.enabled<br />
properties.logs.retentionPolicy.days<br />
properties.workspaceId<br />
properties.storageAccountId<br />
properties.eventHubName<br />
<br />
<br />


## Azure_Synapse_NetSec_Dont_Allow_Universal_IP_Range 

### Display Name 
Do not use Any-to-Any IP range for Azure Synapse Workspace

### Rationale 
Using the firewall feature ensures that access to the data or the service is restricted to a specific set/group of clients. For effective usage, allow only the required IPs. Allowing larger ranges like 0.0.0.0/0, 0.0.0.0/1, 128.0.0.0/1, etc. will defeat the purpose.

### Control Settings 
```json 
  {
    "IPRangeStartIP": "0.0.0.0",
    "IPRangeEndIP": "255.255.255.255"
  }
```

### Control Spec 

> **Passed:**
>Custom firewall rule (PublicNetworkAccess) is disabled.
>Custom firewall rule with Any-to-Any IP range with Start IP address as 0.0.0.0 and End Ip address as 255.255.255.255 is NOT found.
>Firewall rule that gets added from "Allow Azure resources to access this resource" is allowed.

> **Failed:**
> Custom firewall rule with Any-to-Any IP range with Start IP address as 0.0.0.0 and End Ip address as 255.255.255.255 is found.


### Recommendation 

- **Azure Portal** 
To remediate unmanaged Synapse Workspace remove Any to Any firewall IP address. 
1. Go to Azure Portal --> your Synapse Workspace  --> Settings --> Networking --> Firewall rules --> Select Any to Any firewall rule (allowAll rule) --> Delete --> Save. 
For accessing Unmanaged Synapse Workspace add individual firewall IP address. 

To remediate managed Synapse Workspace disable public network access. 
1. Go to Azure Portal --> your Synapse Workspace  --> Settings --> Networking --> Public network access to workspace endpoints --> Disabled --> Save. For accessing Managed Synapse Workspace, configure private endpoint connection. To configure private endpoint connection refer: https://learn.microsoft.com/en-us/azure/synapse-analytics/security/how-to-connect-to-workspace-with-private-links.
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list Synapse workspaces at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Synapse/workspaces?api-version=2021-06-01<br />

- REST API used to list Firewall rules for Synapse workspace:
/subscriptions/{subscriptionId}/resourceGroups/{1}/providers/Microsoft.Synapse/workspaces/{synapseWorkspaceName}/firewallRules?api-version=2021-06-01

**Properties:**
name<br />
properties.startIpAddress<br />
properties.endIpAddress<br />
<br />
