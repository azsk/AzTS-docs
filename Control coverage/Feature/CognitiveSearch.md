# Cognitive Search

**Resource Type:** Microsoft.Search/searchServices

<!-- TOC -->

- [Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only](#azure_aisearch_authz_enable_role_based_api_access_only)
- [Azure_IoTHubs_Audit_Enable_Diagnostic_Settings](#azure_iothubs_audit_enable_diagnostic_settings)
- [Azure_AISearch_AuthN_Use_Managed_Service_Identity](#azure_aisearch_authn_use_managed_service_identity)
- [Azure_AISearch_Audit_Enable_Diagnostic_Settings](#azure_aisearch_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only
 

### Display Name 
Protect Azure AI Search Instances by only allowing RBAC API Access

### Rationale 
Disabling key-based API access control mitigates the risk of unauthorized access, ensuring that only authenticated users with appropriate credentials can interact with the service. This security measure aligns with best practices, protecting sensitive data and system integrity.

### Control Spec 

> **Passed:** 
> Role based API access is enabled on Azure AI search (disableLocalAuth property is true).
> 
> **Failed:** 
> Role based API access is disabled on Azure AI search (disableLocalAuth property is false).

 
### Recommendation 

- **Azure Portal** 
    Remediation Steps for failed Configurations: 
    >   1. In the Azure portal, navigate to your search service. 
    >   2. In the left-navigation pane, select Keys. 
    >   3. Select Role-based access control. 
    
    For more information, please refer: https://learn.microsoft.com/en-us/azure/search/search-security-rbac?tabs=config-svc-portal%2Croles-portal%2Ctest-portal%2Ccustom-role-portal%2Cdisable-keys-portal.

### Azure Policies or REST APIs used for evaluation 

- REST API used to list Azure AI search and its related properties at Subscription level:
/subscriptions/{0}/providers/Microsoft.Search/searchServices?api-version=2023-11-01<br />
**Properties:**
properties.disableLocalAuth

<br />

___



## Azure_AISearch_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in Azure AI Search

### Rationale 
Auditing logs and metrics must be enabled as they provide details for investigation in case of a security breach for threats

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
        "OperationLogs"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> Diagnostic settings should meet the following conditions:
>   1. Diagnostic logs are enabled.
>   2. At least one of the below setting configured:
>       a. Log Analytics.
>       b. Storage account with min Retention period of 90 or forever(Retention period 0).
>       c. Event Hub.
> 
> **Failed:** 
> If any of the below conditions are meet:
>   1.Diagnostic settings should meet the following conditions:
>       a. All diagnostic logs are not enabled.
>       b. No logs destination is configured:
>          i. Log Analytics.
>          ii. Storage account with min Retention period of 90 or forever(Retention period 0).
>          iii. Event Hub.
>   2. Diagnostics setting is disabled for resource.

 
### Recommendation 

- **Azure Portal** 
    - You can change the diagnostic settings from the Azure Portal by following the steps given here: https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/monitoring#configure-diagnostic-settings and while updating the diagnostic settings 'Operation Logs' category of logs and minimum required retention period is of 90 days.
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list diagnostic settings and its related properties at Resource level:
/{ResourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview<br />
**Properties:**
properties.metrics.category,properties.metrics.enabled,properties.metrics.retentionPolicy.enabled, properties.metrics.retentionPolicy.days
properties.logs.category, properties.logs.categorygroup,properties.logs.enabled,properties.metrics.logs.enabled, properties.logs.retentionPolicy.days, name, properties.workspaceId,properties.storageAccountId,properties.eventHubName

- REST API used to list diagnostic category group mapping and its related properties at Resource level:
/{ResourceId}/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview <br />
**Properties:**
properties.categoryGroups, name
<br />
<br />
___ 


## Azure_AISearch_AuthN_Use_Managed_Service_Identity
 

### Display Name 
Managed Service Identity (MSI) must be used in Azure AI Search

### Rationale 
Managed Service Identity (MSI) allows your app to easily access other AAD-protected resources such as Azure Key Vault. The identity is managed by the Azure platform and eliminates the need to provision/manage/rotate any secrets thus reducing the overall risk.

### Control Spec 

> **Passed:** 
> Managed Service Identity (MSI) is enabled on Azure AI Search (identity.type is set to "SystemAssigned").
> 
> **Failed:** 
> Managed Service Identity (MSI) is not enabled on Azure AI Search (identity.type is null or not set to "SystemAssigned").

 
### Recommendation 

- **Azure Portal** 
    Remediation Steps for failed Configurations: 
    >   1. In the Azure portal, navigate to your search service. 
    >   2. In the left-navigation pane, select Settings -> Identity. 
    >   3. Under the "System assigned" tab, toggle the status to "On" and save the changes.   
    
    For more information, please refer: https://learn.microsoft.com/en-us/azure/search/search-howto-managed-identities-data-sources?tabs=portal-sys%2Cportal-user.

### Azure Policies or REST APIs used for evaluation 

- REST API used to list Azure AI search and its related properties at Subscription level:
`/subscriptions/{0}/providers/Microsoft.Search/searchServices?api-version=2023-11-01`<br />
**Properties:**
`identity.type`

<br />

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
