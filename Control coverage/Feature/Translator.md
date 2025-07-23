# Translator

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_Translator_Audit_Enable_Diagnostic_Settings](#azure_translator_audit_enable_diagnostic_settings)
- [Azure_Translator_AuthN_Disable_Local_Auth](#azure_translator_authn_disable_local_auth)
- [Azure_Translator_AuthN_Use_Managed_Service_Identity](#azure_translator_authn_use_managed_service_identity)
- [Azure_Translator_NetSec_Restrict_Public_Network_Access](#azure_translator_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_Translator_Audit_Enable_Diagnostic_Settings

### Display Name
Azure Translator should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure Translator ensures that resource logs and metrics are collected and sent to a Log Analytics workspace, Event Hub, or Storage Account. This is critical for monitoring, auditing, and investigating security incidents, as well as for maintaining compliance with regulatory requirements such as ISO 27001, SOC, and GDPR. Without diagnostic logs, it is difficult to track access patterns, detect anomalous activities, or perform forensic analysis.

### Control Spec

> **Passed:**
> - Diagnostic settings are enabled for the Azure Translator (Cognitive Services) resource.
> - Logs are being sent to at least one of the following: Log Analytics workspace, Event Hub, or Storage Account.
>
> **Failed:**
> - No diagnostic settings are configured for the Azure Translator resource.
> - Logs are not being sent to any destination.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure Portal.
    2. Go to **Cognitive Services** and select your Translator resource.
    3. In the left pane, select **Diagnostic settings** under the **Monitoring** section.
    4. Click **+ Add diagnostic setting**.
    5. Enter a name for the setting.
    6. Select the logs and metrics you want to collect.
    7. Choose at least one destination: **Log Analytics workspace**, **Event Hub**, or **Storage Account**.
    8. Click **Save**.

- **PowerShell**
    ```powershell
    # Replace the variables with your resource details
    $resourceGroup = "<ResourceGroupName>"
    $accountName = "<TranslatorAccountName>"
    $diagnosticName = "<DiagnosticSettingName>"
    $workspaceId = "<LogAnalyticsResourceId>"

    Set-AzDiagnosticSetting -ResourceId "/subscriptions/<subscription-id>/resourceGroups/$resourceGroup/providers/Microsoft.CognitiveServices/accounts/$accountName" `
        -WorkspaceId $workspaceId `
        -Name $diagnosticName `
        -Enabled $true `
        -Category "AuditLogs"
    ```

- **Azure CLI**
    ```bash
    # Replace the variables with your resource details
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscription-id>/resourceGroups/<ResourceGroupName>/providers/Microsoft.CognitiveServices/accounts/<TranslatorAccountName>" \
      --name <DiagnosticSettingName> \
      --workspace <LogAnalyticsResourceId> \
      --logs '[{"category": "AuditLogs", "enabled": true}]'
    ```

- **Automation/Remediation**
    - You can use Azure Policy to enforce that diagnostic settings are enabled for all Cognitive Services accounts:
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.CognitiveServices/accounts"
            },
            {
              "field": "Microsoft.CognitiveServices/accounts/diagnosticSettings[*]",
              "exists": "false"
            }
          ]
        },
        "then": {
          "effect": "deployIfNotExists",
          "details": {
            "type": "Microsoft.Insights/diagnosticSettings",
            "existenceCondition": {
              "field": "Microsoft.Insights/diagnosticSettings/logs.enabled",
              "equals": "true"
            },
            "roleDefinitionIds": [
              "/providers/microsoft.authorization/roleDefinitions/owner"
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
                      "name": "[parameters('diagnosticSettingName')]",
                      "dependsOn": [],
                      "properties": {
                        "workspaceId": "[parameters('logAnalyticsWorkspaceId')]",
                        "logs": [
                          {
                            "category": "AuditLogs",
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
    - For bulk remediation, use AzTS or Azure Policy at the subscription or management group level to audit and deploy diagnostic settings across all Translator resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview`<br />
**Properties:** `logs.enabled`, `workspaceId`, `eventHubAuthorizationRuleId`, `storageAccountId`

<br/>

___

___

## Azure_Translator_AuthN_Disable_Local_Auth

### Display Name
Azure Translator Cognitive Service should have local authentication methods disabled

### Rationale
Disabling local authentication methods (such as account keys) for Azure Translator Cognitive Service accounts enforces the use of Azure Active Directory (Azure AD) authentication. This enhances security by ensuring that only authorized users and applications can access the Translator resource, reduces the risk of key leakage, and supports compliance with regulatory requirements for strong authentication and access control.

### Control Spec

> **Passed:**
> - The Azure Translator Cognitive Service account has local authentication methods (account keys) disabled, and only Azure AD authentication is permitted.
>
> **Failed:**
> - The Azure Translator Cognitive Service account allows local authentication methods (account keys), permitting access without Azure AD authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure Portal**.
    2. Go to **Cognitive Services** and select your **Translator** resource.
    3. In the left pane, select **Networking** or **Security** (depending on UI version).
    4. Locate the **Local authentication** or **Allow access to keys** setting.
    5. Set **Local authentication** to **Disabled**.
    6. Save your changes.

- **PowerShell**
    ```powershell
    # Requires Az.CognitiveServices module
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-translator-account>"

    Update-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName `
      -Name $accountName `
      -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Requires Azure CLI 2.30.0 or later
    az cognitiveservices account update \
      --name <your-translator-account> \
      --resource-group <your-resource-group> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - **Azure Policy:** Deploy or assign the built-in policy definition:  
      **Name:** Cognitive Services accounts should disable local authentication methods  
      **Policy Definition:**  
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.CognitiveServices/accounts"
            },
            {
              "field": "Microsoft.CognitiveServices/accounts/properties.disableLocalAuth",
              "notEquals": true
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      }
      ```
    - **Bulk Remediation:** Use Azure Policy remediation tasks to enforce this setting across all Translator accounts in your subscription or management group.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
  **Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_Translator_AuthN_Use_Managed_Service_Identity

### Display Name
Require Managed Identity Authentication for Azure Translator

### Rationale
Enforcing the use of Managed Service Identity (MSI) for Azure Translator ensures that applications authenticate securely without the need to manage credentials or secrets. This reduces the risk of credential leakage, supports automated rotation, and aligns with Azure security best practices and compliance requirements such as ISO 27001 and SOC 2.

### Control Spec

> **Passed:**
> - Azure Translator resource is configured to require authentication using a system-assigned or user-assigned managed identity.
>
> **Failed:**
> - Azure Translator resource allows authentication using keys or other non-managed identity methods.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Translator (Cognitive Services) resource.
    2. Select **Identity** under the **Settings** section.
    3. Enable **System assigned managed identity** or add a **User assigned managed identity**.
    4. Update your application's authentication logic to use Azure Active Directory (AAD) token-based authentication with the managed identity, instead of using keys.
    5. Remove any stored keys or credentials from your application configuration.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity
    az cognitiveservices account identity assign --name <TranslatorResourceName> --resource-group <ResourceGroupName>

    # Remove keys (if applicable)
    az cognitiveservices account keys regenerate --name <TranslatorResourceName> --resource-group <ResourceGroupName> --key-name key1
    az cognitiveservices account keys regenerate --name <TranslatorResourceName> --resource-group <ResourceGroupName> --key-name key2
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity
    az cognitiveservices account identity assign --name <TranslatorResourceName> --resource-group <ResourceGroupName>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce managed identity authentication for Cognitive Services accounts:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
              },
              {
                "not": {
                  "field": "identity.type",
                  "in": ["SystemAssigned", "UserAssigned"]
                }
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For tenant-wide enforcement, assign the above policy at the subscription or management group level.
    - Use Azure Blueprints or ARM templates to deploy Translator resources with managed identity enabled by default.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`
  <br />
  **Properties:** `identity.type` (should be `SystemAssigned` or `UserAssigned`), `properties.authMode` (should be set to `AAD` or equivalent if available)

<br/>

___

___

## Azure_Translator_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure Translator

### Rationale
Restricting public network access to Azure Translator ensures that only authorized private endpoints or trusted networks can access the resource. This reduces the attack surface, prevents unauthorized access, and helps organizations comply with security and regulatory requirements such as ISO 27001, SOC 2, and GDPR. Enforcing network restrictions is a key security best practice for protecting sensitive data processed by cognitive services.

### Control Spec

> **Passed:**
> - The Azure Translator (Cognitive Services) account has public network access disabled, or
> - The account is configured to allow access only from selected networks or private endpoints.
>
> **Failed:**
> - The Azure Translator account allows public network access (i.e., is accessible from any network, including the internet).

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Translator (Cognitive Services) resource.
    2. In the left menu, select **Networking**.
    3. Under **Public network access**, select **Disabled** to block all public access, or select **Selected networks** to allow only specific virtual networks or IP addresses.
    4. Click **Save** to apply changes.

- **PowerShell**
    ```powershell
    # Disable public network access for a Cognitive Services account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-translator-account>"

    Update-AzCognitiveServicesAccount `
        -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -PublicNetworkAccess "Disabled"
    ```

- **Azure CLI**
    ```bash
    # Disable public network access for a Cognitive Services account
    az cognitiveservices account update \
        --name <your-translator-account> \
        --resource-group <your-resource-group> \
        --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can deploy the built-in Azure Policy:  
      `Cognitive Services accounts should restrict public network access`
      - Policy Definition ID: `/providers/Microsoft.Authorization/policyDefinitions/5c8e2e1c-2b4c-4c1e-8c3a-6c1c1b8d7d87`
      - Assign this policy to enforce or audit the restriction of public network access on Cognitive Services accounts.
    - **ARM Template Example:**
      ```json
      {
        "type": "Microsoft.CognitiveServices/accounts",
        "apiVersion": "2022-12-01",
        "name": "<your-translator-account>",
        "properties": {
          "publicNetworkAccess": "Disabled"
        }
      }
      ```
    - **Bulk Remediation:**  
      Use Azure Policy's "Remediate" feature to automatically update non-compliant Translator accounts across your tenant.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
  **Properties:** `publicNetworkAccess`

<br/>

___


