# MachineLearningWorkspace

**Resource Type:** Microsoft.MachineLearningServices/workspaces
<!-- TOC -->

- [Azure_MachineLearningWorkspace_Audit_Enable_Diagnostics_Log](#azure_machinelearningworkspace_audit_enable_diagnostics_log)
- [Azure_MachineLearningWorkspace_AuthN_Disable_SSH_Authentication](#azure_machinelearningworkspace_authn_disable_ssh_authentication)
- [Azure_MachineLearningWorkspace_Netsec_Configure_VNet](#azure_machinelearningworkspace_netsec_configure_vnet)
- [Azure_MachineLearningWorkspace_NetSec_Dont_Allow_Public_Network_Access](#azure_machinelearningworkspace_netsec_dont_allow_public_network_access)
- [Azure_MachineLearningWorkspace_NetSec_Use_Private_Endpoint](#azure_machinelearningworkspace_netsec_use_private_endpoint)
- [Azure_MachineLearningWorkspace_NetSec_Use_Trusted_Connections](#azure_machinelearningworkspace_netsec_use_trusted_connections)
- [Azure_MachineLearningWorkspace_SI_Use_Latest_OS_Image](#azure_machinelearningworkspace_si_use_latest_os_image)
- [Azure_AIFoundry_AuthN_Use_Managed_Service_Identity](#azure_aifoundry_authn_use_managed_service_identity)
- [Azure_AIFoundry_DP_Enable_Encryption_With_Customer_Managed_Keys](#azure_aifoundry_dp_enable_encryption_with_customer_managed_keys)
- [Azure_AIFoundry_DP_ServerlessAPI_Enable_ContentSafety](#azure_aifoundry_dp_serverlessapi_enable_contentsafety)
- [Azure_AIFoundry_NetSec_Use_Trusted_Connections](#azure_aifoundry_netsec_use_trusted_connections)
- [Azure_MachineLearningWorkspace_DP_Enable_Encryption_With_Customer_Managed_Keys](#azure_machinelearningworkspace_dp_enable_encryption_with_customer_managed_keys)
- [Azure_MachineLearningWorkspace_DP_ServerlessAPI_Enable_ContentSafety](#azure_machinelearningworkspace_dp_serverlessapi_enable_contentsafety)- [Azure_MultiServiceAccount_DP_Data_Loss_Prevention](#Azure_MultiServiceAccount_DP_Data_Loss_Prevention)
<!-- /TOC -->
<br/>

___

## Azure_MachineLearningWorkspace_Audit_Enable_Diagnostics_Log

### Display Name
Diagnostics logs must be enabled for Azure Machine Learning workspace

### Rationale
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings {
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "AmlComputeClusterEvent",
        "AmlComputeClusterNodeEvent",
        "AmlComputeJobEvent",
        "AmlComputeCpuGpuUtilization",
        "AmlRunStatusChangedEvent",
        "ModelsChangeEvent",
        "ModelsReadEvent",
        "ModelsActionEvent",
        "DeploymentReadEvent",
        "DeploymentEventACI",
        "DeploymentEventAKS",
        "InferencingOperationAKS",
        "InferencingOperationACI",
        "EnvironmentChangeEvent",
        "EnvironmentReadEvent",
        "DataLabelChangeEvent",
        "DataLabelReadEvent",
        "ComputeInstanceEvent",
        "DataStoreChangeEvent",
        "DataStoreReadEvent",
        "DataSetChangeEvent",
        "DataSetReadEvent",
        "PipelineChangeEvent",
        "PipelineReadEvent",
        "RunEvent",
        "RunReadEvent"
    ],
    "DiagnosticMinRetentionPeriod":"365"
}
### Control Spec

> **Passed:**
> 1. Required diagnostic logs are enabled.
> 2. At least one of the below settings configured:

>   >- Log Analytics.
>   >- Storage account with min Retention period of 365 or forever(Retention period 0).
>   >- Event Hub.
> 
>
> **Failed:**
> 1. Diagnostics setting is disabled for resource.
> 
>       or
>
> 2. Diagnostic settings meet the following conditions:
> a. All diagnostic logs are not enabled.
> b. None of the below settings is configured:

>   >- Log Analytics.
>   >- Storage account with min Retention period of 365 or forever(Retention period 0).
>   >- Event Hub.
> 

### Recommendation

- **Azure Portal**

  Create or update the diagnostic settings from the Azure Portal by following the steps given here: https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings?tabs=portal#create-diagnostic-settings.


### Azure Policies or REST APIs used for evaluation
- REST API to list all the Machine Learning Workspaces under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2023-04-01
  <br />

- REST API to list diagnostic setting details of MachineLearningWorkspace resources: {resourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview <br />
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


___

## Azure_MachineLearningWorkspace_AuthN_Disable_SSH_Authentication

### Display Name
Disable SSH Authentication for the Machine Learning Workspace Compute

### Rationale
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions.

### Control Settings {
  "CoveredComputeTypes": [
    "ComputeInstance",
    "AmlCompute"
  ]
}
### Control Spec

> **Passed:**
> Local authentication is disabled on all Machine Learning Workspace compute(s).

>  Or

> No compute instance is present for Machine Learning Workspace.

> **Failed:**
> Local authentication is not disabled on MachineLearningWorkspace compute.
> 

### Recommendation

- **Azure Portal**

  To disable SSH on Azure Machine Learning Compute resources, create a new compute instance having SSH disabled.


### Azure Policies or REST APIs used for evaluation

- REST API to list all the Machine Learning Workspaces under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2023-04-01
  <br />

- REST API to list all the Machine Learning Workspace computes : /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspacename}/computes?api-version=2023-04-01
  <br />
  **Properties:** [\*].properties.computeType, [\*].properties.disableLocalAuth
  <br />
  <br />

___

## Azure_MachineLearningWorkspace_Netsec_Configure_VNet

### Display Name
Azure Machine Learning workspace compute services must be connected to a virtual network

### Rationale
Azure Virtual Networks provide enhanced security and isolation for your Azure Machine Learning Compute Clusters and Instances, as well as subnets, access control policies, and other features to further restrict access. When a compute is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.

### Control Settings {
  "AllowedComputeType": [
    "ComputeInstance",
    "AmlCompute"
  ]
}
### Control Spec

> **Passed:**
> All compute instances are connected with Virtual Network.

> Or

> Compute instances are not of type defined in control settings.
> 
> **Failed:**
> 
> Any of the compute instances is not connected with Virtual Network.

### Recommendation

- **Azure Portal**

  To configure virtual network on Azure Machine Learning Compute resources, create a new compute instance with attached virtual networks.

### Azure Policies or REST APIs used for evaluation

- REST API to list all the Machine Learning Workspaces under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2023-04-01
  <br />

- REST API to list all the Machine Learning Workspace computes : /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspacename}/computes?api-version=2023-04-01
  <br />
  **Properties:** [\*].properties.computeType, [\*].properties.properties.subnet.id
  <br />
  <br />

___

## Azure_MachineLearningWorkspace_NetSec_Dont_Allow_Public_Network_Access

### Display Name
Public network access on Machine Learning Workspace should be disabled

### Rationale
Machine Learning Workspace firewall should be enabled so that the Machine Learning Workspace is not accessible by default to any public IPs.

### Control Spec

> **Passed:**
> Public Network Access is configured as Disabled.
> 
> **Failed:**
> Public Network Access is not configured as Disabled.
> 

### Recommendation

- **Azure Portal**

  To remediate, disable public network access on your Machine Learning Workspace. Go to Azure Portal --> your Machine Learning workspace  --> Settings --> Networking --> Public access --> Public network access --> Select on 'Disabled' --> Save"

### Azure Policies or REST APIs used for evaluation

- REST API to list all the Machine Learning Workspaces under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2023-04-01
  <br />
  <br />
  **Properties:** properties.publicNetworkAccess
  <br />
  <br />

___

## Azure_MachineLearningWorkspace_NetSec_Use_Private_Endpoint

### Display Name
Machine Learning Workspace must use private endpoints

### Rationale
Private endpoints provide secure, private connectivity to Machine Learning Workspaces over the Azure backbone network, eliminating exposure to the public internet. This ensures that ML workspace access is restricted to authorized networks and reduces the attack surface significantly.

### Control Settings {
    "RequirePrivateEndpoints": true,
    "DisablePublicAccess": true
}

### Control Spec

> **Passed:**
> Private endpoints are configured and in use for the Machine Learning Workspace.
>
> **Failed:**
> Private endpoints are not configured for the Machine Learning Workspace.
>

### Recommendation

- **Azure Portal**

    Go to Machine Learning Workspace → Networking → Private endpoint connections → Add private endpoint → Configure private endpoint with appropriate virtual network and subnet → Ensure public network access is disabled.

- **PowerShell**# Create private endpoint for Machine Learning Workspace
New-AzPrivateEndpoint -ResourceGroupName $rgName -Name "ml-workspace-pe" -Location $location -Subnet $subnet -PrivateLinkServiceId $workspaceId -GroupId "amlworkspace"
    
    # Disable public network access
    Update-AzMLWorkspace -ResourceGroupName $rgName -Name $workspaceName -PublicNetworkAccess "Disabled"### Azure Policies or REST APIs used for evaluation

- REST API to check private endpoint connections: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}<br />
**Properties:** properties.privateEndpointConnections, properties.publicNetworkAccess<br />

___

## Azure_MachineLearningWorkspace_SI_Use_Latest_OS_Image

### Display Name
Azure Machine Learning compute instances must be recreated to get the latest software updates

### Rationale
Ensure Azure Machine Learning compute instances run on the latest available operating system. Security is improved and vulnerabilities reduced by running with the latest security patches. For more information, visit https://learn.microsoft.com/en-us/azure/machine-learning/concept-vulnerability-management?view=azureml-api-2#compute-instance.

### Control Settings { 
  "CoveredComputeTypes": [
    "ComputeInstance"
  ]
}
### Control Spec

> **Passed:**
> All compute instances are configured with latest OS image version.

>Or

> No compute instance available for Machine Learning Workspace.
> 
> **Failed:**
> Any of the compute instances is not configured with latest OS image version.
> 

### Recommendation

- **Azure Portal**

  To update the OS image of an Azure Machine Learning Compute Instance, create a new compute instance. For more information, visit https://learn.microsoft.com/en-us/azure/machine-learning/concept-vulnerability-management?view=azureml-api-2#compute-instance.


### Azure Policies or REST APIs used for evaluation
- REST API to list all the Machine Learning Workspaces under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2023-04-01
  <br />

- REST API to list all the Machine Learning Workspace computes : /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspacename}/computes?api-version=2023-04-01
  <br />
  **Properties:** [\*].properties.computeType, [\*].properties.properties.osImageMetadata.isLatestOsImageVersion
  <br />
  <br />

<br />
<br />

___

## Azure_AIFoundry_AuthN_Use_Managed_Service_Identity

### Display Name
Managed Service Identity (MSI) must be used in Compute Instances of Azure AI Foundry

### Rationale
Enabling managed identity for Azure AI Foundry compute instances ensures secure and seamless access to Azure resources without the need to manage credentials. Managed identities eliminate the risk of credential leakage and simplify the management of secrets, enhancing the overall security posture of the workspace.

### Control Settings {
  "ExcludedMachineLearningKinds": ["Default", "FeatureStore"],
  "AllowedManagedIdentityTypes": ["SystemAssigned", "SystemAssigned,UserAssigned", "UserAssigned"]
}
### Control Spec

> **Passed:**
> Compute instances have managed identity enabled with appropriate configuration.
>
> **Failed:**
> Compute instances do not have managed identity enabled or configuration is invalid.
>

### Recommendation

- **Azure Portal**

    Go to Azure Portal → your AI Foundry resource → Click "Launch Studio" → Navigate to Management center → Compute → Create or update compute instance → Enable "Assign a managed identity" → Choose either 'System-assigned' or 'User-assigned' identity.

### Azure Policies or REST APIs used for evaluation

- REST API to list compute instances: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/computes<br />
**Properties:** properties.computeType, identity.type, identity.principalId<br />

<br />

___

## Azure_AIFoundry_DP_Enable_Encryption_With_Customer_Managed_Keys

### Display Name
Azure AI Foundry must enable encryption with customer-managed keys

### Rationale
Customer-managed keys provide enhanced security and compliance capabilities by allowing organizations to maintain control over their encryption keys and meet regulatory requirements for data protection.

### Control Spec

> **Passed:**
> Customer-managed key encryption is enabled.
>
> **Failed:**
> Customer-managed key encryption is not enabled.
>

### Recommendation

- **Azure Portal**

    Configure customer-managed keys during workspace creation or update existing workspace encryption settings through Azure Portal → AI Foundry workspace → Encryption → Configure customer-managed keys.

### Azure Policies or REST APIs used for evaluation

- REST API to get workspace configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}<br />
**Properties:** properties.encryption.status, properties.encryption.keyVaultProperties<br />

<br />

___

## Azure_AIFoundry_DP_ServerlessAPI_Enable_ContentSafety

### Display Name
AI Foundry serverless APIs must enable content safety features

### Rationale
Content safety features help detect and filter harmful content in AI applications, ensuring responsible AI deployment and protecting against potential misuse.

### Control Spec

> **Passed:**
> Content safety features are enabled for serverless APIs.
>
> **Failed:**
> Content safety features are not enabled or configured.
>

### Recommendation

- **Azure Portal**

    Enable content safety through AI Foundry Studio → Safety + Security → Content safety → Configure content filtering and safety policies for your models.

### Azure Policies or REST APIs used for evaluation

- REST API to check content safety configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/onlineEndpoints<br />
**Properties:** properties.contentSafety.enabled<br />

<br />

___

## Azure_AIFoundry_NetSec_Use_Trusted_Connections

### Display Name
AI Foundry must use trusted network connections

### Rationale
Using trusted network connections ensures that data transmission is secure and protected against unauthorized access and interception.

### Control Spec

> **Passed:**
> Trusted network connections are configured and in use.
>
> **Failed:**
> Trusted network connections are not properly configured.
>

### Recommendation

- **Azure Portal**

    Configure trusted connections through virtual networks, private endpoints, and secure connectivity options in your AI Foundry workspace network settings.

### Azure Policies or REST APIs used for evaluation

- REST API to check network configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}<br />
**Properties:** properties.publicNetworkAccess, properties.privateEndpointConnections<br />

<br />

___

## Azure_MachineLearningWorkspace_DP_Enable_Encryption_With_Customer_Managed_Keys

### Display Name
Machine Learning Workspace must enable encryption with customer-managed keys

### Rationale
Customer-managed keys provide enhanced security and compliance capabilities by allowing organizations to maintain control over their encryption keys and meet regulatory requirements for data protection.

### Control Spec

> **Passed:**
> Customer-managed key encryption is enabled.
>
> **Failed:**
> Customer-managed key encryption is not enabled.
>

### Recommendation

- **Azure Portal**

    Configure customer-managed keys during workspace creation or update existing workspace encryption settings through Azure Portal → Machine Learning workspace → Encryption → Configure customer-managed keys.

### Azure Policies or REST APIs used for evaluation

- REST API to get workspace configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}<br />
**Properties:** properties.encryption.status, properties.encryption.keyVaultProperties<br />

<br />

___

## Azure_MachineLearningWorkspace_DP_ServerlessAPI_Enable_ContentSafety

### Display Name
Machine Learning Workspace serverless APIs must enable content safety features

### Rationale
Content safety features help detect and filter harmful content in AI applications, ensuring responsible AI deployment and protecting against potential misuse.

### Control Spec

> **Passed:**
> Content safety features are enabled for serverless APIs.
>
> **Failed:**
> Content safety features are not enabled or configured.
>

### Recommendation

- **Azure Portal**

    Enable content safety through Machine Learning Studio → Configure content filtering and safety policies for your models and endpoints.

### Azure Policies or REST APIs used for evaluation

- REST API to check content safety configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/onlineEndpoints<br />
**Properties:** properties.contentSafety.enabled<br />

<br />

___

## Azure_MachineLearningWorkspace_NetSec_Use_Trusted_Connections

### Display Name  
ML Workspace must use trusted network connections

### Rationale
Trusted connections ensure ML workspaces communicate only through secure, authenticated, and encrypted network channels.

### Control Settings 
```json
{
  "RequireTrustedConnections": true,
  "AllowPublicAccess": false
}
```

### Control Specs
- **Passed:** Trusted connections configured
- **Failed:** Untrusted connection methods allowed

### Recommendation
Configure private endpoints and disable public access for ML workspace.

### Control Evaluation Details:
- **Method Name:** CheckMLWorkspaceTrustedConnections
- **Control Severity:** High
- **Evaluation Frequency:** Daily

<br />

## Azure_MultiServiceAccount_DP_Data_Loss_Prevention

### Display Name 
Multi-Service Account must implement data loss prevention

### Rationale 
Data Loss Prevention controls protect sensitive information processed by multi-service accounts from unauthorized exposure or exfiltration.

### Control Settings
```json
{
  "RequireContentFiltering": true,
  "EnablePrivateEndpoints": true,
  "RestrictDataExport": true
}
```

### Control Spec 
- **Passed:** DLP controls are configured
- **Failed:** Missing data protection controls

### Recommendation
Configure content filtering and private endpoints for multi-service accounts.

### Control Evaluation Details:
- **Method Name:** CheckMultiServiceAccountDLP
- **Control Severity:** High
- **Evaluation Frequency:** Daily