# AIFoundry

**Resource Type:** Microsoft.MachineLearningServices/workspaces

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_AIFoundry_Audit_Enable_Diagnostic_Settings](#azure_aifoundry_audit_enable_diagnostic_settings)
- [Azure_AIFoundry_DP_Avoid_Plaintext_Secrets](#azure_aifoundry_dp_avoid_plaintext_secrets)
- [Azure_AIFoundry_NetSec_Disable_Public_Network_Access](#azure_aifoundry_netsec_disable_public_network_access)
- [Azure_AIFoundry_NetSec_Enable_NetworkIsolation](#azure_aifoundry_netsec_enable_networkisolation)
- [Azure_AIFoundry_AuthN_Use_Managed_Service_Identity](#azure_aifoundry_authn_use_managed_service_identity)
- [Azure_AIFoundry_DP_Enable_Encryption_With_Customer_Managed_Keys](#azure_aifoundry_dp_enable_encryption_with_customer_managed_keys)
- [Azure_AIFoundry_DP_ServerlessAPI_Enable_ContentSafety](#azure_aifoundry_dp_serverlessapi_enable_contentsafety)
- [Azure_AIFoundry_NetSec_Use_Trusted_Connections](#azure_aifoundry_netsec_use_trusted_connections)

<!-- /TOC -->
<br/>

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


## Azure_AIFoundry_Audit_Enable_Diagnostic_Settings

### Display Name
Azure AI Foundry workspaces should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure AI Foundry (Machine Learning Services) workspaces ensures that all control and operational activities are logged and exported to a Log Analytics workspace, Event Hub, or Storage Account. This is critical for security monitoring, auditing, and compliance requirements, as it provides visibility into resource operations and user activities. Diagnostic logs help organizations detect anomalous activities, investigate incidents, and meet regulatory standards such as ISO 27001, SOC, and GDPR.

### Control Spec

> **Passed:**
> - Diagnostic settings are enabled for the Azure AI Foundry (Machine Learning Services) workspace.
> - Logs are being sent to at least one of the following: Log Analytics workspace, Event Hub, or Storage Account.
>
> **Failed:**
> - No diagnostic settings are configured for the workspace.
> - Logs are not being exported to any destination.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure Machine Learning workspace** in the Azure portal.
    2. In the left pane, select **Diagnostic settings** under **Monitoring**.
    3. Click **+ Add diagnostic setting**.
    4. Provide a name for the setting.
    5. Select the log categories and metrics you wish to collect.
    6. Choose at least one destination: **Log Analytics workspace**, **Event Hub**, or **Storage Account**.
    7. Click **Save**.

- **PowerShell**
    ```powershell
    # Replace variables with your values
    $resourceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.MachineLearningServices/workspaces/<workspace-name>"
    $diagnosticSettingName = "<diagnostic-setting-name>"
    $workspaceId = "<log-analytics-workspace-resource-id>"

    Set-AzDiagnosticSetting -ResourceId $resourceId `
        -WorkspaceId $workspaceId `
        -Name $diagnosticSettingName `
        -Enabled $true `
        -Category "AllLogs"
    ```

- **Azure CLI**
    ```bash
    # Replace placeholders with your values
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.MachineLearningServices/workspaces/<workspace-name>" \
      --name "<diagnostic-setting-name>" \
      --workspace "<log-analytics-workspace-resource-id>" \
      --logs '[{"category": "AllLogs", "enabled": true}]'
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      Use the built-in policy definition:  
      `Deploy Diagnostic Settings for Machine Learning Services to Log Analytics workspace`
      This policy can be assigned at the subscription or management group level to enforce and automatically deploy diagnostic settings.
    - **ARM Template:**  
      Diagnostic settings can be configured using ARM templates for bulk or automated deployment.
    - **AzTS Remediation Script:**  
      If using Azure Tenant Security (AzTS), leverage the provided remediation script to configure diagnostic settings across multiple workspaces.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview`  
**Properties:**  
- `logs.enabled`
- `workspaceId` or `eventHubAuthorizationRuleId` or `storageAccountId`

<br/>

___

___

## Azure_AIFoundry_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext in Azure AI Foundry Data Plane resources

### Rationale
Storing secrets such as API keys, passwords, or connection strings in plaintext within Azure AI Foundry Data Plane resources poses a significant security risk. Plaintext secrets can be easily accessed by unauthorized users or compromised accounts, leading to potential data breaches, privilege escalation, and non-compliance with regulatory standards (such as ISO 27001, SOC 2, and GDPR). Ensuring that secrets are securely stored using Azure Key Vault or other managed secret stores helps protect sensitive information and maintain a strong security posture.

### Control Spec

> **Passed:**
> - No secrets (e.g., passwords, API keys, connection strings) are found in plaintext within configuration files, environment variables, or resource properties of Azure AI Foundry Data Plane resources.
> - All secrets are referenced securely via Azure Key Vault or an equivalent managed secret store.
>
> **Failed:**
> - Any secret is detected in plaintext within configuration files, environment variables, or resource properties of Azure AI Foundry Data Plane resources.
> - Secrets are not referenced via secure secret management solutions.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure AI Foundry workspace.
    2. Review all configuration files, environment variables, and resource properties for any plaintext secrets.
    3. Remove any plaintext secrets and replace them with references to Azure Key Vault secrets.
    4. Ensure that applications and services are configured to retrieve secrets securely from Azure Key Vault.

- **PowerShell**
    ```powershell
    # Example: Set a Key Vault reference in an environment variable
    $keyVaultName = "<your-keyvault-name>"
    $secretName = "<your-secret-name>"
    $secretUri = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName).Id

    # Set the environment variable to reference the Key Vault secret
    [System.Environment]::SetEnvironmentVariable("MY_SECRET", $secretUri, "User")
    ```

- **Azure CLI**
    ```bash
    # Retrieve a secret from Azure Key Vault
    az keyvault secret show --vault-name <your-keyvault-name> --name <your-secret-name> --query value -o tsv

    # Set an environment variable to reference the Key Vault secret (Linux example)
    export MY_SECRET=$(az keyvault secret show --vault-name <your-keyvault-name> --name <your-secret-name> --query value -o tsv)
    ```

- **Automation/Remediation**
    - Use Azure Policy to audit and deny deployment of resources containing plaintext secrets.
    - Implement CI/CD pipeline checks to scan for plaintext secrets in configuration files and environment variables.
    - Use tools such as Microsoft Security DevOps or open-source scanners (e.g., GitHub's secret scanning) to detect and remediate plaintext secrets.
    - Example Azure Policy definition snippet:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.AIFoundry/workspaces"
              },
              {
                "anyOf": [
                  {
                    "field": "Microsoft.AIFoundry/workspaces/configuration",
                    "contains": "password"
                  },
                  {
                    "field": "Microsoft.AIFoundry/workspaces/configuration",
                    "contains": "apiKey"
                  }
                ]
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, consider using Azure Tenant Security (AzTS) scripts to scan and remove plaintext secrets across all workspaces.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AIFoundry/workspaces/{workspaceName}?api-version=2024-01-01`
  <br />
  **Properties:** `.properties.configuration`, `.properties.environmentVariables` (scanned for plaintext secrets such as passwords, API keys, connection strings)

<br/>

___

___

## Azure_AIFoundry_NetSec_Disable_Public_Network_Access

### Display Name
Disable public network access for Azure AI Foundry workspaces

### Rationale
Disabling public network access for Azure AI Foundry workspaces ensures that resources are not accessible from the public internet, reducing the attack surface and mitigating risks of unauthorized access. Restricting access to private endpoints or trusted networks helps organizations comply with regulatory requirements such as ISO 27001, SOC 2, and NIST, and strengthens the overall security posture of AI workloads.

### Control Spec

> **Passed:**
> - Public network access is disabled for the Azure AI Foundry workspace.
>
> **Failed:**
> - Public network access is enabled, allowing resources to be accessed from the public internet.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure AI Foundry workspace in the Azure Portal.
    2. Under the "Networking" section, locate the "Public network access" setting.
    3. Set "Public network access" to **Disabled**.
    4. Save your changes.

- **PowerShell**
    ```powershell
    # Replace <resourceGroupName> and <workspaceName> with your values
    Update-AzResource -ResourceType "Microsoft.AIFoundry/workspaces" `
      -ResourceGroupName "<resourceGroupName>" `
      -ResourceName "<workspaceName>" `
      -PropertyObject @{ publicNetworkAccess = "Disabled" } `
      -ApiVersion "2023-01-01" `
      -Force
    ```

- **Azure CLI**
    ```bash
    # Replace <resource-group> and <workspace-name> with your values
    az resource update \
      --resource-type "Microsoft.AIFoundry/workspaces" \
      --name <workspace-name> \
      --resource-group <resource-group> \
      --set properties.publicNetworkAccess=Disabled \
      --api-version 2023-01-01
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.AIFoundry/workspaces"
              },
              {
                "field": "Microsoft.AIFoundry/workspaces/publicNetworkAccess",
                "notEquals": "Disabled"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - **Bulk Remediation:** Use Azure Policy to audit and enforce this setting across all AI Foundry workspaces in your tenant.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AIFoundry/workspaces/{workspaceName}?api-version=2023-01-01`<br />
**Properties:** `publicNetworkAccess`

<br/>

___

___

## Azure_AIFoundry_NetSec_Enable_NetworkIsolation

### Display Name
Enable network isolation for Azure AI Foundry workspaces

### Rationale
Enabling network isolation for Azure AI Foundry workspaces ensures that resources are protected from unauthorized public network access. By restricting access to private endpoints or virtual networks, organizations can prevent data exfiltration, reduce the attack surface, and comply with regulatory requirements such as ISO 27001, SOC 2, and GDPR. Network isolation is a critical security control for safeguarding sensitive AI workloads and maintaining compliance with industry standards.

### Control Spec

> **Passed:**
> - The Azure AI Foundry workspace is configured with network isolation enabled.
> - All inbound and outbound traffic is restricted to approved virtual networks or private endpoints.
>
> **Failed:**
> - The Azure AI Foundry workspace is accessible from public networks.
> - Network isolation is not enabled, or resources are not restricted to private endpoints or virtual networks.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure AI Foundry workspace in the Azure Portal.
    2. Under "Networking," select "Private endpoint connections."
    3. Click "Add" to create a new private endpoint and associate it with your workspace.
    4. Ensure "Public network access" is set to "Disabled" in the workspace's networking settings.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Disable public network access and enable private endpoint for an Azure ML workspace
    $resourceGroup = "<your-resource-group>"
    $workspaceName = "<your-workspace-name>"

    # Update workspace to disable public network access
    az ml workspace update `
      --name $workspaceName `
      --resource-group $resourceGroup `
      --public-network-access Disabled

    # Create a private endpoint (example)
    az network private-endpoint create `
      --name <private-endpoint-name> `
      --resource-group $resourceGroup `
      --vnet-name <vnet-name> `
      --subnet <subnet-name> `
      --private-connection-resource-id "/subscriptions/<subscription-id>/resourceGroups/$resourceGroup/providers/Microsoft.MachineLearningServices/workspaces/$workspaceName" `
      --group-ids workspace
    ```

- **Azure CLI**
    ```bash
    # Disable public network access for the workspace
    az ml workspace update \
      --name <your-workspace-name> \
      --resource-group <your-resource-group> \
      --public-network-access Disabled

    # Create a private endpoint (example)
    az network private-endpoint create \
      --name <private-endpoint-name> \
      --resource-group <your-resource-group> \
      --vnet-name <vnet-name> \
      --subnet <subnet-name> \
      --private-connection-resource-id "/subscriptions/<subscription-id>/resourceGroups/<your-resource-group>/providers/Microsoft.MachineLearningServices/workspaces/<your-workspace-name>" \
      --group-ids workspace
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:** Deploy the built-in policy `AzureML workspaces should have public network access disabled` to enforce network isolation.
    - **ARM Template Example:**
        ```json
        {
          "type": "Microsoft.MachineLearningServices/workspaces",
          "apiVersion": "2023-04-01",
          "name": "[parameters('workspaceName')]",
          "location": "[parameters('location')]",
          "properties": {
            "publicNetworkAccess": "Disabled"
          }
        }
        ```
    - **Bulk Remediation:** Use Azure Policy remediation tasks to apply the policy across all subscriptions or management groups.
    - **Compliance Frameworks:** Helps meet requirements for ISO 27001, SOC 2, GDPR, and other regulatory standards.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}?api-version=2023-04-01`  
**Properties:** `properties.publicNetworkAccess` (should be set to `Disabled`)

<br/>

___
