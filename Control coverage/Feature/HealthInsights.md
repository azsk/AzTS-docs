# Health Insights

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_HealthInsights_Audit_Enable_Diagnostic_Settings](#azure_healthinsights_audit_enable_diagnostic_settings)
- [Azure_HealthInsights_AuthN_Disable_Local_Auth](#azure_healthinsights_authn_disable_local_auth)
- [Azure_HealthInsights_AuthN_Use_Managed_Service_Identity](#azure_healthinsights_authn_use_managed_service_identity)
- [Azure_HealthInsights_NetSec_Restrict_Public_Network_Access](#azure_healthinsights_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_HealthInsights_Audit_Enable_Diagnostic_Settings

### Display Name
Azure Health Insights workspaces should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure Health Insights workspaces ensures that all management and operational activities are logged and sent to a Log Analytics workspace, Event Hub, or Storage Account. This is essential for monitoring, auditing, and investigating security incidents. Diagnostic logs provide visibility into access and configuration changes, supporting compliance with regulatory requirements and organizational security policies.

### Control Spec

> **Passed:**  
> Diagnostic settings are enabled on the Azure Health Insights workspace and are configured to send logs to at least one of the following: Log Analytics workspace, Event Hub, or Storage Account.
>
> **Failed:**  
> Diagnostic settings are not enabled, or logs are not being sent to any destination (Log Analytics, Event Hub, or Storage Account).

### Recommendation

- **Azure Portal**  
    1. Navigate to the **Azure Health Insights** workspace in the Azure Portal.  
    2. In the left pane, select **Diagnostic settings** under the **Monitoring** section.  
    3. Click **+ Add diagnostic setting**.  
    4. Provide a name for the diagnostic setting.  
    5. Select the log categories you want to collect (e.g., AuditLogs, OperationalLogs).  
    6. Choose at least one destination:  
        - **Send to Log Analytics workspace**  
        - **Archive to a storage account**  
        - **Stream to an event hub**  
    7. Click **Save**.

- **PowerShell**
    ```powershell
    # Install the Az module if not already installed
    Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

    # Set variables
    $resourceGroupName = "<ResourceGroupName>"
    $workspaceName = "<HealthInsightsWorkspaceName>"
    $diagnosticName = "<DiagnosticSettingName>"
    $logAnalyticsWorkspaceId = "<LogAnalyticsResourceId>"

    # Enable diagnostic settings
    Set-AzDiagnosticSetting -ResourceId "/subscriptions/<subscriptionId>/resourceGroups/$resourceGroupName/providers/Microsoft.HealthInsights/workspaces/$workspaceName" `
        -WorkspaceId $logAnalyticsWorkspaceId `
        -Name $diagnosticName `
        -Enabled $true `
        -Category "AuditLogs","OperationalLogs"
    ```

- **Azure CLI**
    ```bash
    # Set variables
    RESOURCE_GROUP="<ResourceGroupName>"
    WORKSPACE_NAME="<HealthInsightsWorkspaceName>"
    DIAGNOSTIC_NAME="<DiagnosticSettingName>"
    LOG_ANALYTICS_ID="<LogAnalyticsResourceId>"

    # Enable diagnostic settings
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscriptionId>/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.HealthInsights/workspaces/$WORKSPACE_NAME" \
      --name $DIAGNOSTIC_NAME \
      --workspace $LOG_ANALYTICS_ID \
      --logs '[{"category": "AuditLogs", "enabled": true}, {"category": "OperationalLogs", "enabled": true}]'
    ```

- **Automation/Remediation**  
    - Use Azure Policy to enforce diagnostic settings on all Health Insights workspaces:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.HealthInsights/workspaces"
              },
              {
                "field": "Microsoft.HealthInsights/workspaces/diagnosticSettings[*].enabled",
                "notEquals": "true"
              }
            ]
          },
          "then": {
            "effect": "deployIfNotExists",
            "details": {
              "type": "Microsoft.Insights/diagnosticSettings",
              "roleDefinitionIds": [
                "/providers/microsoft.authorization/roleDefinitions/..."
              ],
              "deployment": {
                "properties": {
                  "mode": "incremental",
                  "template": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": "1.0.0.0",
                    "resources": [
                      {
                        "type": "Microsoft.Insights/diagnosticSettings",
                        "apiVersion": "2021-05-01-preview",
                        "name": "[parameters('diagnosticSettingName')]",
                        "dependsOn": [],
                        "properties": {
                          "workspaceId": "[parameters('logAnalyticsWorkspaceId')]",
                          "logs": [
                            {
                              "category": "AuditLogs",
                              "enabled": true
                            },
                            {
                              "category": "OperationalLogs",
                              "enabled": true
                            }
                          ]
                        }
                      }
                    ]
                  },
                  "parameters": {
                    "diagnosticSettingName": {
                      "value": "<DiagnosticSettingName>"
                    },
                    "logAnalyticsWorkspaceId": {
                      "value": "<LogAnalyticsResourceId>"
                    }
                  }
                }
              }
            }
          }
        }
        ```
    - Use Azure Policy [DeployIfNotExists] initiative to ensure all new and existing workspaces have diagnostic settings enabled.
    - For bulk remediation, use an automation script to enumerate all Health Insights workspaces and apply diagnostic settings as shown above.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthInsights/workspaces/{workspaceName}/providers/microsoft.insights/diagnosticSettings/{name}?api-version=2021-05-01-preview`  
**Properties:**  
- `logs[*].enabled`  
- `workspaceId`  
- `eventHubAuthorizationRuleId`  
- `storageAccountId`  

<br/>

___

___

## Azure_HealthInsights_AuthN_Disable_Local_Auth

### Display Name
Disable local authentication for Azure Health Insights

### Rationale
Disabling local authentication for Azure Health Insights workspaces ensures that only Azure Active Directory (Azure AD) identities can access the resource. This reduces the risk of credential compromise and enforces stronger, centralized identity management and access control. Enabling only Azure AD authentication helps organizations meet compliance requirements and adhere to security best practices by eliminating legacy authentication mechanisms that may be more vulnerable to attacks.

### Control Spec

> **Passed:**
> Local authentication is disabled for the Azure Health Insights workspace. Only Azure AD authentication is permitted.
>
> **Failed:**
> Local authentication is enabled for the Azure Health Insights workspace, allowing access using workspace keys or other non-Azure AD credentials.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Health Insights** and select your workspace.
    3. In the left pane, select **Settings** > **Authentication**.
    4. Locate the **Local authentication** setting.
    5. Set **Local authentication** to **Disabled**.
    6. Click **Save** to apply the changes.

- **PowerShell**
    ```powershell
    # Replace with your resource group and workspace name
    $resourceGroupName = "<your-resource-group>"
    $workspaceName = "<your-workspace-name>"

    # Disable local authentication
    Update-AzResource -ResourceType "Microsoft.HealthInsights/workspaces" `
        -ResourceGroupName $resourceGroupName `
        -ResourceName $workspaceName `
        -ApiVersion "2023-03-01-preview" `
        -PropertyObject @{"properties" = @{"disableLocalAuth" = $true}} `
        -Force
    ```

- **Azure CLI**
    ```bash
    # Replace with your resource group and workspace name
    az resource update \
      --resource-type "Microsoft.HealthInsights/workspaces" \
      --name "<your-workspace-name>" \
      --resource-group "<your-resource-group>" \
      --set properties.disableLocalAuth=true \
      --api-version 2023-03-01-preview
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that local authentication is disabled on all Health Insights workspaces.
    - Example Azure Policy definition:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.HealthInsights/workspaces"
              },
              {
                "field": "Microsoft.HealthInsights/workspaces/disableLocalAuth",
                "notEquals": "true"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use a script to iterate over all workspaces and set `disableLocalAuth` to `true` using PowerShell or Azure CLI.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthInsights/workspaces/{workspaceName}?api-version=2023-03-01-preview`  
**Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_HealthInsights_AuthN_Use_Managed_Service_Identity

### Display Name
Azure Health Insights resources should use Managed Service Identity (MSI) for authentication

### Rationale
Requiring Azure Health Insights resources to use Managed Service Identity (MSI) for authentication ensures that applications and services access Azure resources securely without managing credentials in code or configuration files. MSI leverages Azure Active Directory (Azure AD) for authentication, reducing the risk of credential leakage, simplifying identity management, and supporting compliance with industry standards such as ISO 27001, SOC 2, and HIPAA.

### Control Spec

> **Passed:**
> - The Azure Health Insights workspace is configured to use a system-assigned or user-assigned managed identity for authentication to Azure resources.
>
> **Failed:**
> - The Azure Health Insights workspace is not configured with any managed identity (system-assigned or user-assigned), or uses explicit credentials (such as connection strings, secrets, or keys) for authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Health Insights workspace in the Azure Portal.
    2. In the left menu, select **Identity** under the **Settings** section.
    3. Under the **System assigned** tab, switch the **Status** to **On** and click **Save**.
    4. (Optional) To assign a user-assigned managed identity, go to the **User assigned** tab, click **Add**, and select the managed identity to assign.
    5. Update your application or service to use the managed identity for authentication to other Azure resources.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity
    $resourceGroup = "<your-resource-group>"
    $workspaceName = "<your-healthinsights-workspace>"
    Set-AzResource -ResourceType "Microsoft.HealthInsights/workspaces" `
        -ResourceGroupName $resourceGroup `
        -ResourceName $workspaceName `
        -IdentityType SystemAssigned
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity
    az healthinsights workspace identity assign \
        --resource-group <your-resource-group> \
        --name <your-healthinsights-workspace>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce the use of managed identities on Health Insights resources:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.HealthInsights/workspaces"
              },
              {
                "field": "identity.type",
                "notEquals": "SystemAssigned"
              }
            ]
          },
          "then": {
            "effect": "audit"
          }
        }
        ```
    - For bulk remediation, use Azure Policy's **DeployIfNotExists** effect to automatically enable managed identities on non-compliant resources.
    - Integrate with Azure Blueprints to ensure all new Health Insights deployments use MSI by default.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthInsights/workspaces/{workspaceName}?api-version=2022-10-01-preview`  
**Properties:** `identity.type` (should be `SystemAssigned` or `UserAssigned`)

<br/>

___

___

## Azure_HealthInsights_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure Health Insights workspaces

### Rationale
Restricting public network access to Azure Health Insights workspaces helps prevent unauthorized access and data exposure. By ensuring that only private endpoints or trusted networks can access the workspace, you reduce the attack surface and comply with security best practices and regulatory requirements such as HIPAA, ISO 27001, and GDPR. This control helps organizations safeguard sensitive health data and maintain compliance with industry standards.

### Control Spec

> **Passed:**  
> Public network access is disabled for the Azure Health Insights workspace, or access is restricted to selected networks/private endpoints only.
>
> **Failed:**  
> Public network access is enabled, allowing connections from all networks (including the internet) to the Azure Health Insights workspace.

### Recommendation

- **Azure Portal**
    1. Navigate to your **Azure Health Insights** workspace in the Azure Portal.
    2. Under **Settings**, select **Networking**.
    3. Set **Public network access** to **Disabled**.
    4. Optionally, configure **Private endpoint connections** or specify **Selected networks** to allow access only from trusted sources.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Disable public network access for a Health Insights workspace
    $resourceGroup = "<your-resource-group>"
    $workspaceName = "<your-workspace-name>"
    Update-AzResource -ResourceType "Microsoft.HealthInsights/workspaces" `
        -ResourceGroupName $resourceGroup `
        -ResourceName $workspaceName `
        -PropertyObject @{ properties = @{ publicNetworkAccess = "Disabled" } } `
        -ApiVersion "2023-03-15-preview"
    ```

- **Azure CLI**
    ```bash
    # Disable public network access for a Health Insights workspace
    az resource update \
      --resource-type "Microsoft.HealthInsights/workspaces" \
      --name <your-workspace-name> \
      --resource-group <your-resource-group> \
      --set properties.publicNetworkAccess=Disabled \
      --api-version 2023-03-15-preview
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      Deploy or assign the following Azure Policy to enforce the restriction:
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.HealthInsights/workspaces"
            },
            {
              "field": "Microsoft.HealthInsights/workspaces/publicNetworkAccess",
              "notEquals": "Disabled"
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      }
      ```
    - **Bulk Remediation:**  
      Use Azure Policy remediation tasks to automatically update non-compliant workspaces.
    - **ARM Template Snippet:**
      ```json
      {
        "type": "Microsoft.HealthInsights/workspaces",
        "apiVersion": "2023-03-15-preview",
        "name": "<your-workspace-name>",
        "properties": {
          "publicNetworkAccess": "Disabled"
        }
      }
      ```

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `PATCH /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthInsights/workspaces/{workspaceName}?api-version=2023-03-15-preview`  
  **Properties:**  
  - `properties.publicNetworkAccess`

<br/>

___


