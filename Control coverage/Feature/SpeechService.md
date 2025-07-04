# Speech Service

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_SpeechService_Audit_Enable_Diagnostic_Settings](#azure_speechservice_audit_enable_diagnostic_settings)
- [Azure_SpeechService_AuthN_Disable_Local_Auth](#azure_speechservice_authn_disable_local_auth)
- [Azure_SpeechService_AuthN_Use_Managed_Service_Identity](#azure_speechservice_authn_use_managed_service_identity)
- [Azure_SpeechService_DP_Data_Loss_Prevention](#azure_speechservice_dp_data_loss_prevention)
- [Azure_SpeechService_NetSec_Restrict_Public_Network_Access](#azure_speechservice_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_SpeechService_AuthN_Use_Managed_Service_Identity

### Display Name
Speech Service must use Managed Service Identity

### Rationale
Managed Service Identity provides secure authentication without storing credentials and enables automatic credential rotation for Speech Services. This eliminates the need to manage API keys and reduces the risk of credential exposure, providing a more secure and manageable authentication mechanism.

### Control Settings {
    "RequireMSI": true,
    "DisableLocalAuth": true,
    "AllowedIdentityTypes": ["SystemAssigned", "UserAssigned", "SystemAssigned,UserAssigned"]
}
### Control Spec

> **Passed:**
> Managed Service Identity is enabled and local authentication is disabled for Speech Service.
>
> **Failed:**
> Managed Service Identity is not configured or local authentication is still enabled.
>

### Recommendation

- **Azure Portal**

    Go to Speech Service resource ? Identity ? Enable system-assigned or user-assigned managed identity ? Navigate to Keys and Endpoint ? Disable local authentication ? Assign appropriate roles for accessing other Azure resources.

- **PowerShell**# Enable MSI and disable local auth for Speech Service
    Set-AzCognitiveServicesAccount -ResourceGroupName $rgName -Name $speechServiceName -IdentityType "SystemAssigned" -DisableLocalAuth $true
    
    # Verify the configuration
    Get-AzCognitiveServicesAccount -ResourceGroupName $rgName -Name $speechServiceName### Azure Policies or REST APIs used for evaluation

- REST API to get Speech Service account properties: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{speechServiceName}<br />
**Properties:** identity.type, identity.principalId, properties.disableLocalAuth<br />

<br />

___

## Azure_SpeechService_Audit_Enable_Diagnostic_Settings

### Display Name
Azure Speech Service should have diagnostic settings enabled

### Rationale

Enabling diagnostic settings for Azure Speech Service ensures that resource-level logs and metrics are collected and exported to a Log Analytics workspace, Event Hub, or Azure Storage account. This is essential for monitoring, auditing, and investigating security incidents, as well as for meeting compliance and governance requirements. Diagnostic logs provide visibility into operations and access patterns, supporting incident response, forensic analysis, and continuous improvement of security posture.

### Control Spec

> **Passed:**
> - The Speech Service resource has at least one diagnostic setting configured, sending logs to a Log Analytics workspace, Event Hub, or Azure Storage account.
>
> **Failed:**
> - The Speech Service resource does not have any diagnostic settings enabled, or no logs are being exported to any destination.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Cognitive Services** and select your Speech Service resource.
    3. In the left pane, select **Diagnostic settings** under **Monitoring**.
    4. Click **+ Add diagnostic setting**.
    5. Enter a name for the setting.
    6. Select the log categories and metrics you want to collect.
    7. Choose at least one destination: Log Analytics workspace, Event Hub, or Storage account.
    8. Click **Save**.

- **PowerShell**
    ```powershell
    # Example: Enable diagnostic settings for a Speech Service resource
    $resourceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
    $workspaceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

    Set-AzDiagnosticSetting -ResourceId $resourceId `
        -WorkspaceId $workspaceId `
        -Name "SpeechServiceDiagnostics" `
        -Enabled $true `
        -Category "AllLogs"
    ```

- **Azure CLI**
    ```bash
    # Example: Enable diagnostic settings for a Speech Service resource
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>" \
      --name "SpeechServiceDiagnostics" \
      --workspace "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>" \
      --logs '[{"category": "AllLogs", "enabled": true}]'
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce diagnostic settings on all Speech Service resources:
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
            "effect": "audit"
          }
        }
        ```
    - For bulk remediation, use AzTS (Azure Tenant Security) scripts or Azure Policy remediation tasks to automatically deploy diagnostic settings to all existing Speech Service resources.
    - ARM Template snippet for deploying diagnostic settings:
        ```json
        {
          "type": "Microsoft.Insights/diagnosticSettings",
          "apiVersion": "2021-05-01-preview",
          "name": "SpeechServiceDiagnostics",
          "dependsOn": [
            "[resourceId('Microsoft.CognitiveServices/accounts', parameters('accountName'))]"
          ],
          "properties": {
            "workspaceId": "[parameters('logAnalyticsWorkspaceId')]",
            "logs": [
              {
                "category": "AllLogs",
                "enabled": true,
                "retentionPolicy": {
                  "enabled": false,
                  "days": 0
                }
              }
            ]
          }
        }
        ```
    - This control helps meet requirements for compliance frameworks such as ISO 27001, SOC 2, and GDPR by ensuring audit logs are retained and accessible.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/Microsoft.Insights/diagnosticSettings?api-version=2017-05-01-preview`<br />
**Properties:** Checks for existence of diagnostic settings and configured destinations (Log Analytics, Event Hub, Storage).

<br/>

___

___

## Azure_SpeechService_AuthN_Disable_Local_Auth

### Display Name
Disable Local Authentication Methods for Azure Speech Service

### Rationale
Disabling local authentication methods (such as API keys) for Azure Speech Service enforces the use of Azure Active Directory (Azure AD) authentication. This enhances security by eliminating static credentials, reducing the risk of credential leakage, and ensuring that only authorized users and applications can access the Speech resource. Enforcing Azure AD authentication aligns with security best practices and helps organizations meet compliance requirements for identity and access management.

### Control Spec

> **Passed:**
> Local authentication methods (e.g., API keys) are disabled on the Azure Speech Service resource. Only Azure AD authentication is allowed.
>
> **Failed:**
> Local authentication methods are enabled, allowing access to the Speech Service resource using API keys or other non-Azure AD credentials.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal: [https://portal.azure.com](https://portal.azure.com)
    2. Go to **Cognitive Services** and select your Speech Service resource.
    3. Under **Settings**, select **Authentication**.
    4. Set **Allow local authentication** to **Disabled**.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Install the Az.CognitiveServices module if not already present
    Install-Module -Name Az.CognitiveServices

    # Disable local authentication for a Speech Service resource
    Update-AzCognitiveServicesAccount `
      -ResourceGroupName "<ResourceGroupName>" `
      -Name "<SpeechServiceAccountName>" `
      -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Disable local authentication for a Speech Service resource
    az cognitiveservices account update \
      --resource-group <ResourceGroupName> \
      --name <SpeechServiceAccountName> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - **Azure Policy Definition**: Use the built-in policy `Cognitive Services accounts should disable local authentication methods` to enforce this setting across your environment.
    - **Bulk Remediation**: Assign the Azure Policy at the subscription or management group level for tenant-wide enforcement.
    - **ARM Template Example**:
        ```json
        {
          "type": "Microsoft.CognitiveServices/accounts",
          "apiVersion": "2022-12-01",
          "name": "<SpeechServiceAccountName>",
          "properties": {
            "disableLocalAuth": true
          }
        }
        ```
    - **AzTS Remediation**: If using Azure Tenant Security (AzTS), leverage the AzTS remediation script for bulk disabling of local authentication on all Speech Service resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
**Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_SpeechService_DP_Data_Loss_Prevention

### Display Name
Enable Data Loss Prevention (DLP) for Azure Speech Service

### Rationale
Data Loss Prevention (DLP) controls help protect sensitive information processed by Azure Speech Service from accidental or unauthorized exposure. Enabling DLP ensures that data such as personally identifiable information (PII), financial data, or proprietary business content is not inadvertently leaked or misused. This control is critical for maintaining compliance with regulatory requirements (such as GDPR, HIPAA, and ISO 27001) and for upholding organizational data governance standards.

### Control Spec

> **Passed:**
> - Azure Speech Service resource has DLP features enabled, such as data logging disabled, endpoint access restricted, and data retention policies configured according to organizational or regulatory requirements.
>
> **Failed:**
> - Azure Speech Service resource does not have DLP features enabled, allows unrestricted data logging, or lacks appropriate data retention and access controls.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure Portal and go to your Speech Service resource (`Microsoft.CognitiveServices/accounts`).
    2. Under **Settings**, select **Diagnostic settings** and ensure that logging is configured according to your DLP policy (e.g., disable unnecessary logging of sensitive data).
    3. Under **Networking**, restrict access to trusted networks using Private Endpoints or IP firewall rules.
    4. Under **Data retention**, configure the retention period to comply with your organization’s DLP requirements.
    5. Review and update the **Privacy Policy URL** and **Usage Guidelines URL** to reflect your organization’s data handling practices.

- **PowerShell**
    ```powershell
    # Example: Update diagnostic settings to restrict data logging
    Set-AzDiagnosticSetting -ResourceId "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}" `
        -WorkspaceId "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}" `
        -Enabled $false

    # Example: Restrict network access
    Update-AzCognitiveServicesAccount -ResourceGroupName "{resourceGroupName}" `
        -Name "{accountName}" `
        -NetworkRuleSet @{defaultAction="Deny"; ipRules=@("x.x.x.x/32")}
    ```

- **Azure CLI**
    ```bash
    # Example: Disable diagnostic logging
    az monitor diagnostic-settings delete \
      --resource "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}" \
      --name "{diagnosticSettingName}"

    # Example: Restrict network access
    az cognitiveservices account network-rule add \
      --resource-group {resourceGroupName} \
      --name {accountName} \
      --ip-address x.x.x.x
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce DLP settings:
        - **Policy Definition Example:** Require that Cognitive Services accounts have network rules configured and diagnostic logging disabled for sensitive data.
    - ARM Template Snippet:
        ```json
        {
          "type": "Microsoft.CognitiveServices/accounts",
          "apiVersion": "2022-12-01",
          "name": "[parameters('accountName')]",
          "properties": {
            "networkAcls": {
              "defaultAction": "Deny",
              "ipRules": [
                {
                  "value": "x.x.x.x/32"
                }
              ]
            }
          }
        }
        ```
    - **Bulk Remediation:** Use Azure Policy remediation tasks to apply network restrictions and disable logging across all Speech Service resources in your tenant.

### Azure Policies or REST APIs used for evaluation

- REST API: `https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`<br />
**Properties:** `networkAcls`, `diagnosticSettings`, `properties.privacyPolicyUri`, `properties.usageGuidelinesUri`, `properties.dataRetention`

<br/>

___

___

## Azure_SpeechService_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure Speech Service

### Rationale
Restricting public network access to Azure Speech Service ensures that only authorized private endpoints or trusted networks can communicate with the resource. This reduces the attack surface by preventing unauthorized or anonymous access from the public internet, thereby strengthening the security posture and supporting compliance with regulatory standards such as ISO 27001, SOC 2, and GDPR.

### Control Spec

> **Passed:**
> - The Azure Speech Service resource is configured to deny public network access (`publicNetworkAccess` is set to `Disabled`).
> - Only private endpoints or trusted virtual networks are allowed.
>
> **Failed:**
> - The Azure Speech Service resource allows public network access (`publicNetworkAccess` is set to `Enabled` or not set).
> - The resource is accessible from the public internet.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Cognitive Services** and select your Speech Service resource.
    3. Under **Networking**, select **Public network access**.
    4. Set **Public network access** to **Disabled**.
    5. Optionally, configure **Private endpoint connections** or **Trusted virtual networks** as needed.
    6. Click **Save**.

- **PowerShell**
    ```powershell
    # Requires Az.CognitiveServices module
    $resourceGroup = "<your-resource-group>"
    $accountName = "<your-speech-service-account>"
    Update-AzCognitiveServicesAccount `
      -ResourceGroupName $resourceGroup `
      -Name $accountName `
      -PublicNetworkAccess Disabled
    ```

- **Azure CLI**
    ```bash
    # Requires Azure CLI 2.7.0+ and extension for cognitiveservices
    az cognitiveservices account update \
      --name <your-speech-service-account> \
      --resource-group <your-resource-group> \
      --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      Deploy or assign the built-in Azure Policy:  
      **Name:** Cognitive Services accounts should restrict public network access  
      **Policy Definition ID:** `/providers/Microsoft.Authorization/policyDefinitions/9a4eeb62-4a6b-4c7c-9e6b-1c7b3c4b9c3b`
    - **ARM Template Snippet:**
      ```json
      {
        "type": "Microsoft.CognitiveServices/accounts",
        "apiVersion": "2022-12-01",
        "name": "<your-speech-service-account>",
        "properties": {
          "publicNetworkAccess": "Disabled"
        }
      }
      ```
    - **Bulk Remediation:**  
      Use Azure Policy's "Remediate" function to apply this setting to all non-compliant resources in your subscription or management group.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
  **Properties:**  
  - `properties.publicNetworkAccess` (should be set to `Disabled`)

<br/>

___


