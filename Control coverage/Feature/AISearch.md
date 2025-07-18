# AISearch

**Resource Type:** Microsoft.Search/searchServices

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_AISearch_Audit_Enable_Diagnostic_Settings](#azure_aisearch_audit_enable_diagnostic_settings)
- [Azure_AISearch_NetSec_Restrict_Public_Network_Access](#azure_aisearch_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_AISearch_Audit_Enable_Diagnostic_Settings

### Display Name
Azure AI Search should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure AI Search ensures that resource logs and metrics are collected and sent to a Log Analytics workspace, Event Hub, or Storage Account. This is critical for monitoring, auditing, and investigating activities within the search service. Diagnostic logs support compliance requirements, enable security monitoring, and help with troubleshooting and incident response.

### Control Spec

> **Passed:**
> - Diagnostic settings are enabled on the Azure AI Search service and are configured to send logs and metrics to at least one of the following: Log Analytics workspace, Event Hub, or Storage Account.
>
> **Failed:**
> - Diagnostic settings are not enabled, or logs/metrics are not being sent to any destination.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure AI Search resource.
    2. In the left pane, select **Diagnostic settings** under the **Monitoring** section.
    3. Click **+ Add diagnostic setting**.
    4. Enter a name for the setting.
    5. Select the log categories and metrics you want to collect.
    6. Choose at least one destination: Log Analytics workspace, Event Hub, or Storage Account.
    7. Click **Save**.

- **PowerShell**
    ```powershell
    # Example: Enable diagnostic settings for an Azure AI Search service
    $resourceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Search/searchServices/<search-service-name>"
    $workspaceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

    Set-AzDiagnosticSetting -ResourceId $resourceId `
        -WorkspaceId $workspaceId `
        -Enabled $true `
        -Name "AISearchDiagnostics" `
        -Category "SearchServiceLogs"
    ```

- **Azure CLI**
    ```bash
    # Example: Enable diagnostic settings for an Azure AI Search service
    az monitor diagnostic-settings create \
      --name "AISearchDiagnostics" \
      --resource "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Search/searchServices/<search-service-name>" \
      --workspace "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>" \
      --logs '[{"category": "SearchServiceLogs", "enabled": true}]'
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce diagnostic settings on all Azure AI Search resources. Example policy definition:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.Search/searchServices"
              },
              {
                "field": "Microsoft.Insights/diagnosticSettings[*].workspaceId",
                "exists": "false"
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
                        "apiVersion": "2017-05-01-preview",
                        "name": "[concat(parameters('searchServiceName'), '-diagnostic')]",
                        "dependsOn": [],
                        "properties": {
                          "workspaceId": "[parameters('logAnalyticsWorkspaceId')]",
                          "logs": [
                            {
                              "category": "SearchServiceLogs",
                              "enabled": true
                            }
                          ]
                        }
                      }
                    ]
                  },
                  "parameters": {
                    "searchServiceName": {
                      "value": "[field('name')]"
                    },
                    "logAnalyticsWorkspaceId": {
                      "value": "<workspace-resource-id>"
                    }
                  }
                }
              }
            }
          }
        }
        ```
    - For bulk or tenant-wide remediation, use Azure Policy Assignments at the subscription or management group level.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Search/searchServices/{searchServiceName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview`<br />
**Properties:** `logs`, `metrics`, `workspaceId`, `eventHubAuthorizationRuleId`, `storageAccountId`

<br/>

___

## Azure_AISearch_NetSec_Restrict_Public_Network_Access

### Display Name
Azure AI Search services must restrict public network access

### Rationale
Restricting public network access to Azure AI Search services helps protect against unauthorized access and data breaches. By limiting access to trusted networks only, organizations can significantly reduce their attack surface and ensure that search indexes and data are only accessible from authorized locations.

### Control Settings {
    "AllowedPublicNetworkAccess": "Disabled",
    "RequirePrivateEndpoints": true,
    "AllowedIPRanges": [],
    "AllowAzureServicesAccess": false
}

### Control Spec

> **Passed:**
> Public network access is disabled or restricted to specific IP ranges with private endpoints configured.
>
> **Failed:**
> Public network access is enabled without restrictions or proper security configuration is missing.

### Recommendation

- **Azure Portal**

    Navigate to Azure Portal → AI Search service → Settings → Networking → Under "Public network access", select "Disabled" → Configure private endpoints for secure access → Save changes.

### Azure Policies or REST APIs used for evaluation

- REST API to get AI Search service details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Search/searchServices/{searchServiceName}<br />
**Properties:** properties.publicNetworkAccess, properties.networkRuleSet, properties.privateEndpointConnections<br />

<br/>

___
