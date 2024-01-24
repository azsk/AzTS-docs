# MachineLearningWorkspace

**Resource Type:** Microsoft.MachineLearningServices/workspaces
<!-- TOC -->

- [Azure_MachineLearningWorkspace_Audit_Enable_Diagnostics_Log](#azure_machinelearningworkspace_audit_enable_diagnostics_log)
- [Azure_MachineLearningWorkspace_AuthN_Disable_SSH_Authentication](#azure_machinelearningworkspace_authn_disable_ssh_authentication)
- [Azure_MachineLearningWorkspace_Netsec_Configure_VNet](#azure_machinelearningworkspace_netsec_configure_vnet)
- [Azure_MachineLearningWorkspace_NetSec_Dont_Allow_Public_Network_Access](#azure_machinelearningworkspace_netsec_dont_allow_public_network_access)
- [Azure_MachineLearningWorkspace_SI_Use_Latest_OS_Image](#azure_machinelearningworkspace_si_use_latest_os_image)

<!-- /TOC -->
<br/>

___

## Azure_MachineLearningWorkspace_Audit_Enable_Diagnostics_Log

### Display Name
Diagnostics logs must be enabled for Azure Machine Learning workspace

### Rationale
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings 
```json 
{
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
```

### Control Spec

> **Passed:**
> 1. Required diagnostic logs are enabled.
> 2. At least one of the below settings configured:
> a. Log Analytics.
> b. Storage account with min Retention period of 365 or forever(Retention period 0).
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

> ii. Storage account with min Retention period of 365 or forever(Retention period 0).

> iii. Event Hub.
> 

### Recommendation

- **Azure Portal**

    Create or update the diagnostic settings from the Azure Portal by following the steps given here: https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings?tabs=portal#create-diagnostic-settings.


### Azure Policies or REST APIs used for evaluation

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

### Control Settings 
```json 
{
  "CoveredComputeTypes": [
    "ComputeInstance",
    "AmlCompute"
  ]
}
```

### Control Spec

> **Passed:**
> Local authentication is disabled on all Machine Learning Workspace compute(s).

> Or

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

### Control Settings 
```json 
{
  "AllowedComputeType": [
    "ComputeInstance",
    "AmlCompute"
  ]
}
 ```  

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
> Public Network Access is not configured as Enabled.
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

## Azure_MachineLearningWorkspace_SI_Use_Latest_OS_Image

### Display Name
Azure Machine Learning compute instances must be recreated to get the latest software updates

### Rationale
Ensure Azure Machine Learning compute instances run on the latest available operating system. Security is improved and vulnerabilities reduced by running with the latest security patches. For more information, visit https://learn.microsoft.com/en-us/azure/machine-learning/concept-vulnerability-management?view=azureml-api-2#compute-instance.

### Control Settings 
```json
{ 
  "CoveredComputeTypes": [
    "ComputeInstance"
  ]
}
 ```  

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



