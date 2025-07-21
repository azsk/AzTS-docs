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
- [Azure_MachineLearningWorkspace_DP_Enable_Encryption_With_Customer_Managed_Keys](#azure_machinelearningworkspace_dp_enable_encryption_with_customer_managed_keys)
- [Azure_MachineLearningWorkspace_DP_ServerlessAPI_Enable_ContentSafety](#azure_machinelearningworkspace_dp_serverlessapi_enable_contentsafety)- 
- [Azure_MultiServiceAccount_DP_Data_Loss_Prevention](#Azure_MultiServiceAccount_DP_Data_Loss_Prevention)
- [Azure_MachineLearning_Workspace_AuthN_Disable_Credential_Based_Access_On_Datastore](#azure_machinelearning_workspace_authn_disable_credential_based_access_on_datastore)
- [Azure_MachineLearning_Workspace_AuthN_Restrict_Key_Based_Auth_Type_Online_End_Points](#azure_machinelearning_workspace_authn_restrict_key_based_auth_type_online_end_points)
- [Azure_MachineLearning_Workspace_AuthN_Use_Managed_Service_Identity](#azure_machinelearning_workspace_authn_use_managed_service_identity)
- [Azure_MachineLearningWorkspace_D_P_Avoid_Plaintext_Secrets](#azure_machinelearningworkspace_d_p_avoid_plaintext_secrets)
- [Azure_MachineLearning_Workspace_NetSec_Restrict_Network_Access](#azure_machinelearning_workspace_netsec_restrict_network_access)


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

### Control Settings 
```json
{
    "RequirePrivateEndpoints": true,
    "DisablePublicAccess": true
}
```

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

___

## Azure_MachineLearningWorkspace_AuthN_Disable_Credential_Based_Access_On_Datastore

### Display Name
Disable credential-based access on Azure Machine Learning datastore

### Rationale
Credential-based access (such as account keys, SAS tokens, or username/password) to Azure Machine Learning datastores increases the risk of credential leakage and unauthorized access. Disabling credential-based authentication enforces the use of more secure authentication mechanisms like managed identities or service principals, thereby improving security posture and supporting compliance with standards such as ISO 27001, SOC 2, and PCI DSS.

### Control Spec

> **Passed:**  
> All Azure Machine Learning datastores in the workspace are configured to disallow credential-based access (e.g., account keys, SAS tokens, username/password). Only secure authentication methods such as managed identities or service principals are enabled.
>
> **Failed:**  
> One or more datastores in the Azure Machine Learning workspace allow credential-based access (e.g., via account keys, SAS tokens, or username/password).

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Machine Learning workspace.
    2. Select **Datastores** from the left menu.
    3. For each datastore, review the authentication method.
    4. If credential-based authentication (account key, SAS, or username/password) is enabled, edit the datastore.
    5. Update the authentication method to use a managed identity or service principal.
    6. Save the changes.

- **PowerShell**
    ```powershell
    # Example: Update a datastore to use managed identity
    $ws = Get-AzMLWorkspace -ResourceGroupName "<ResourceGroup>" -Name "<WorkspaceName>"
    Update-AzMLDatastore `
      -WorkspaceName $ws.Name `
      -ResourceGroupName $ws.ResourceGroupName `
      -Name "<DatastoreName>" `
      -AuthenticationType "ManagedIdentity"
    ```

- **Azure CLI**
    ```bash
    # Example: Update a datastore to use managed identity
    az ml datastore update --name <DatastoreName> \
      --workspace-name <WorkspaceName> \
      --resource-group <ResourceGroup> \
      --identity-type "SystemAssigned"
    ```

- **Automation/Remediation**
    - **Azure Policy:**  
      Deploy an Azure Policy that audits or denies datastores configured with credential-based access.  
      Example policy definition snippet:
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.MachineLearningServices/workspaces/datastores"
            },
            {
              "field": "Microsoft.MachineLearningServices/workspaces/datastores/authenticationType",
              "in": ["AccountKey", "SasToken", "UsernamePassword"]
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      }
      ```
    - **Bulk Remediation:**  
      Use PowerShell or Azure CLI scripts to enumerate all datastores in a subscription or tenant and update their authentication method to managed identity or service principal.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/datastores?api-version=2023-04-01`  
**Properties:**  
- `authenticationType` (should not be `AccountKey`, `SasToken`, or `UsernamePassword`)

<br/>

___


## Azure_MachineLearningWorkspace_AuthN_Restrict_Key_Based_AuthType_OnlineEndPoints

### Display Name
Restrict Key-Based Authentication for Azure Machine Learning Online Endpoints

### Rationale
Disabling key-based authentication for Azure Machine Learning online endpoints ensures that only Azure Active Directory (Azure AD) authentication is used. This enhances security by enforcing identity-based access controls, reducing the risk of unauthorized access due to leaked or mismanaged keys. Compliance frameworks such as ISO 27001, SOC 2, and NIST 800-53 emphasize strong authentication mechanisms and minimizing the use of static credentials.

### Control Spec

> **Passed:**
> - All Azure Machine Learning online endpoints within the workspace have key-based authentication disabled.
> - Only Azure AD authentication is enabled for all endpoints.
>
> **Failed:**
> - One or more online endpoints in the workspace allow key-based authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Machine Learning workspace.
    2. In the left menu, select **Endpoints** > **Online endpoints**.
    3. For each endpoint, select the endpoint name to open its details.
    4. Under the **Authentication** section, ensure that **Key-based authentication** is disabled and **Azure Active Directory** authentication is enabled.
    5. Save changes.

- **PowerShell**
    ```powershell
    # List all online endpoints in a workspace
    az ml online-endpoint list --workspace-name <workspace-name> --resource-group <resource-group-name>

    # Update an endpoint to disable key-based authentication
    az ml online-endpoint update --name <endpoint-name> --workspace-name <workspace-name> --resource-group <resource-group-name> --set auth_mode=AAD
    ```

- **Azure CLI**
    ```bash
    # List all online endpoints in a workspace
    az ml online-endpoint list --workspace-name <workspace-name> --resource-group <resource-group-name>

    # Update an endpoint to use Azure AD authentication only
    az ml online-endpoint update --name <endpoint-name> --workspace-name <workspace-name> --resource-group <resource-group-name> --set auth_mode=AAD
    ```

- **Automation/Remediation**
    - Use Azure Policy to audit or enforce that key-based authentication is disabled for all online endpoints. Example policy definition:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints"
              },
              {
                "field": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/authMode",
                "equals": "Key"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use scripting to iterate through all endpoints and update their authentication mode to Azure AD.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/onlineEndpoints/{endpointName}?api-version=2023-04-01`
  <br />
  **Properties:** `properties.authMode` (should be set to `AAD`)

<br/>

___

___

## Azure_MachineLearningWorkspace_AuthN_Use_Managed_Service_Identity

### Display Name
Azure Machine Learning Workspace should use Managed Service Identity (MSI) for Authentication

### Rationale
Enabling Managed Service Identity (MSI) for Azure Machine Learning Workspaces ensures that the workspace can securely access Azure resources without the need to manage credentials in code. MSI leverages Azure Active Directory (Azure AD) to provide an automatically managed identity, reducing the risks associated with credential leakage and simplifying identity management. This control helps organizations meet compliance requirements for secure authentication and aligns with best practices for least privilege and credential management.

### Control Spec

> **Passed:**
> - The Azure Machine Learning Workspace is configured to use a system-assigned or user-assigned Managed Service Identity (MSI) for authentication.
>
> **Failed:**
> - The Azure Machine Learning Workspace is not configured with a Managed Service Identity, or MSI is disabled.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Machine Learning** and select the target workspace.
    3. Under **Settings**, select **Identity**.
    4. Set the **Status** to **On** for System-assigned managed identity.
    5. Optionally, add a user-assigned managed identity if required.
    6. Click **Save**.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity for an Azure ML workspace
    $resourceGroupName = "<your-resource-group>"
    $workspaceName = "<your-workspace-name>"

    Set-AzMlWorkspace -ResourceGroupName $resourceGroupName `
                      -Name $workspaceName `
                      -AssignIdentity
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity for an Azure ML workspace
    az ml workspace update \
      --name <your-workspace-name> \
      --resource-group <your-resource-group> \
      --assign-identity
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that all Azure Machine Learning Workspaces have MSI enabled:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.MachineLearningServices/workspaces"
              },
              {
                "field": "identity.type",
                "notEquals": "SystemAssigned"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use Azure Policy's "DeployIfNotExists" effect to automatically enable MSI on non-compliant workspaces.
    - ARM Template snippet to enable MSI:
        ```json
        {
          "type": "Microsoft.MachineLearningServices/workspaces",
          "apiVersion": "2023-04-01",
          "name": "[parameters('workspaceName')]",
          "identity": {
            "type": "SystemAssigned"
          }
        }
        ```

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}?api-version=2023-04-01`  
**Properties:** `identity.type` (should be `SystemAssigned` or include `UserAssigned`)

<br/>

___

___

## Azure_MachineLearningWorkspace_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext in Azure Machine Learning Workspace

### Rationale
Storing sensitive information such as secrets, passwords, or keys in plaintext within Azure Machine Learning Workspace resources poses a significant security risk. Plaintext secrets can be easily accessed by unauthorized users, leading to potential data breaches, privilege escalation, or compromise of other connected resources. Enforcing secure secret management practices helps organizations comply with regulatory requirements (such as ISO 27001, SOC 2, and GDPR) and strengthens the overall security posture of the Azure environment.

### Control Spec

> **Passed:**
> - No secrets, passwords, or sensitive authentication information are stored in plaintext properties of the Azure Machine Learning Workspace or its associated resources.
> - All secrets are referenced securely using Azure Key Vault or other approved secret management solutions.
>
> **Failed:**
> - Any secret, password, or sensitive authentication information is found stored in plaintext within the Azure Machine Learning Workspace resource properties or configuration files.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Machine Learning Workspace in the Azure Portal.
    2. Review all workspace properties, compute targets, and environment variables for any plaintext secrets.
    3. Remove any plaintext secrets and replace them with references to Azure Key Vault secrets.
    4. Ensure all authentication credentials are stored and accessed securely using Azure Key Vault integration.

- **PowerShell**
    ```powershell
    # Example: Remove or update a workspace property containing a plaintext secret
    $workspace = Get-AzMLWorkspace -ResourceGroupName "<ResourceGroup>" -Name "<WorkspaceName>"
    # Remove or update sensitive properties as needed
    # Integrate Key Vault for secret management
    Set-AzMLWorkspace -ResourceGroupName "<ResourceGroup>" -Name "<WorkspaceName>" -KeyVault "<KeyVaultResourceId>"
    ```

- **Azure CLI**
    ```bash
    # Example: Update workspace to use Key Vault for secrets
    az ml workspace update --name <WorkspaceName> --resource-group <ResourceGroup> --key-vault <KeyVaultResourceId>
    ```

- **Automation/Remediation**
    - Use Azure Policy to audit and deny the creation of resources with plaintext secrets.
    - Implement Azure Policy definitions to enforce the use of Azure Key Vault for secret management.
    - Regularly scan workspace configurations and environment variables for plaintext secrets using automated scripts or Azure Security Center recommendations.
    - Example Azure Policy snippet:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.MachineLearningServices/workspaces"
              },
              {
                "not": {
                  "field": "Microsoft.MachineLearningServices/workspaces/keyVault",
                  "exists": "true"
                }
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use Azure Resource Graph queries to identify all workspaces with potential plaintext secrets and automate updates via PowerShell or Azure CLI scripts.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}?api-version=2023-04-01`
  <br />
  **Properties:** Review all user-defined properties, environment variables, and linked service configurations for plaintext secrets or sensitive information.

<br/>

___


## Azure_MachineLearningWorkspace_NetSec_Restrict_Network_Access

### Display Name
Restrict Network Access to Azure Machine Learning Workspace

### Rationale
Restricting network access to Azure Machine Learning Workspaces ensures that only authorized networks and users can access sensitive machine learning resources and data. This control reduces the attack surface by preventing unauthorized access from public networks, thus helping organizations comply with security best practices and regulatory requirements such as ISO 27001, SOC 2, and GDPR.

### Control Spec

> **Passed:**
> - The Azure Machine Learning Workspace has public network access disabled, or
> - The workspace is configured to allow access only from selected virtual networks and subnets (using Private Endpoint or Service Endpoint).
>
> **Failed:**
> - The Azure Machine Learning Workspace allows public network access, or
> - The workspace is not restricted to selected networks and is accessible from the public internet.

### Recommendation

- **Azure Portal**
    1. Navigate to **Azure Machine Learning** > **Workspaces**.
    2. Select the target workspace.
    3. Under **Networking**, set **Public access** to **Disabled**.
    4. Configure **Private Endpoint** or restrict access to selected virtual networks/subnets as required.
    5. Save the configuration.

- **PowerShell**
    ```powershell
    # Disable public network access for an Azure ML Workspace
    $resourceGroupName = "<your-resource-group>"
    $workspaceName = "<your-ml-workspace>"
    Update-AzMLWorkspace `
      -ResourceGroupName $resourceGroupName `
      -Name $workspaceName `
      -PublicNetworkAccess "Disabled"
    ```

- **Azure CLI**
    ```bash
    # Disable public network access for an Azure ML Workspace
    az ml workspace update \
      --name <your-ml-workspace> \
      --resource-group <your-resource-group> \
      --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:** Use the built-in policy `Azure Machine Learning workspaces should have public network access disabled` to enforce this control across your subscriptions.
    - **ARM Template Snippet:**
        ```json
        {
          "type": "Microsoft.MachineLearningServices/workspaces",
          "apiVersion": "2023-04-01",
          "name": "<your-ml-workspace>",
          "properties": {
            "publicNetworkAccess": "Disabled"
          }
        }
        ```
    - **Bulk Remediation:** Use Azure Policy remediation tasks to automatically update non-compliant workspaces.

### Azure Policies or REST APIs used for evaluation

- **REST API:** `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}?api-version=2023-04-01`  
**Properties:** `properties.publicNetworkAccess`

<br/>

___
