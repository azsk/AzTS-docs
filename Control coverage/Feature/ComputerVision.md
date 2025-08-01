# Computer Vision

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ComputerVision_Audit_Enable_Diagnostic_Settings](#azure_computervision_audit_enable_diagnostic_settings)
- [Azure_ComputerVision_AuthN_Disable_Local_Auth](#azure_computervision_authn_disable_local_auth)
- [Azure_ComputerVision_AuthN_Use_Managed_Service_Identity](#azure_computervision_authn_use_managed_service_identity)
- [Azure_ComputerVision_DP_Data_Loss_Prevention](#azure_computervision_dp_data_loss_prevention)
- [Azure_ComputerVision_NetSec_Restrict_Public_Network_Access](#azure_computervision_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_ComputerVision_AuthN_Use_Managed_Service_Identity

### Display Name
Computer Vision must use Managed Service Identity

### Rationale
Managed Service Identity eliminates the need to store credentials in code and provides secure access to other Azure services without managing secrets.

### Control Spec

> **Passed:**
> Managed Service Identity is enabled and configured.
>
> **Failed:**
> Managed Service Identity is not enabled.
>

### Recommendation

- **Azure Portal**

    Go to Computer Vision resource ? Identity ? Enable system-assigned or user-assigned managed identity ? Assign appropriate roles for accessing other Azure resources.

### Azure Policies or REST APIs used for evaluation

- REST API to get identity configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}<br />
**Properties:** identity.type, identity.principalId<br />

<br />

___

## Azure_ComputerVision_Audit_Enable_Diagnostic_Settings

### Display Name
Audit enabling of diagnostic settings for Azure Computer Vision accounts

### Rationale
Enabling diagnostic settings for Azure Computer Vision accounts ensures that resource logs and metrics are sent to a Log Analytics workspace, Event Hub, or Storage Account. This is critical for monitoring, auditing, and incident response, and supports compliance with regulatory requirements such as GDPR, ISO 27001, and SOC 2. Diagnostic logs provide visibility into operations and access patterns, helping to detect and investigate anomalous or unauthorized activities.

### Control Spec

> **Passed:**
> - The Azure Computer Vision account has diagnostic settings enabled, sending logs to at least one of the following: Log Analytics workspace, Event Hub, or Storage Account.
>
> **Failed:**
> - The Azure Computer Vision account does not have diagnostic settings configured, or is not sending logs to any supported destination.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Cognitive Services** and select your **Computer Vision** account.
    3. In the left pane, select **Diagnostic settings** under **Monitoring**.
    4. Click **+ Add diagnostic setting**.
    5. Enter a name for the setting.
    6. Select the log and metric categories to collect.
    7. Choose at least one destination: **Log Analytics workspace**, **Storage account**, or **Event Hub**.
    8. Click **Save**.

- **PowerShell**
    ```powershell
    # Replace variables with your actual values
    $resourceGroupName = "<resource-group>"
    $accountName = "<computer-vision-account>"
    $diagnosticName = "<diagnostic-setting-name>"
    $workspaceId = "<log-analytics-workspace-resource-id>"

    Set-AzDiagnosticSetting -ResourceId "/subscriptions/<subscription-id>/resourceGroups/$resourceGroupName/providers/Microsoft.CognitiveServices/accounts/$accountName" `
        -WorkspaceId $workspaceId `
        -Name $diagnosticName `
        -Enabled $true `
        -Category "AllMetrics","AuditLogs"
    ```

- **Azure CLI**
    ```bash
    # Replace variables with your actual values
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>" \
      --name <diagnostic-setting-name> \
      --workspace <log-analytics-workspace-resource-id> \
      --logs '[{"category": "AuditLogs", "enabled": true}]' \
      --metrics '[{"category": "AllMetrics", "enabled": true}]'
    ```

- **Automation/Remediation**
    - **Azure Policy:** Deploy the built-in policy definition:  
      **Name:** *Deploy Diagnostic Settings for Cognitive Services to Log Analytics workspace*  
      **Definition ID:** `/providers/Microsoft.Authorization/policyDefinitions/0ec5e3e7-2c4b-4f7e-9c0d-2e5b1b4d2b8c`  
      This policy can automatically deploy diagnostic settings to all Cognitive Services accounts, including Computer Vision.
    - **ARM Template:** You can use an ARM template to enforce diagnostic settings deployment at scale.
    - **AzTS Remediation:** If using Azure Tenant Security (AzTS), refer to the AzTS remediation script for bulk enabling diagnostic settings across all Cognitive Services accounts.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview`  
**Properties:** `logs`, `metrics`, `workspaceId`, `eventHubAuthorizationRuleId`, `storageAccountId`

<br/>

___

## Azure_ComputerVision_AuthN_Disable_Local_Auth

### Display Name
Disable local authentication methods for Azure Computer Vision accounts

### Rationale
Disabling local authentication methods (such as account keys) for Azure Computer Vision accounts helps to enforce stronger authentication mechanisms like Azure Active Directory (Azure AD). This reduces the risk of credential leakage and unauthorized access, and aligns with security best practices and compliance requirements such as ISO 27001, SOC 2, and NIST SP 800-53. Enforcing Azure AD authentication ensures that access to the Computer Vision resource is managed through centralized identity and access management, supporting auditability and conditional access policies.

### Control Spec

> **Passed:**
> - The Azure Computer Vision account has all local authentication methods (such as API keys) disabled.
> - Only Azure Active Directory authentication is enabled for the resource.
>
> **Failed:**
> - The Azure Computer Vision account allows local authentication (API keys) to be used for access.
> - Any local authentication method is enabled on the resource.

### Recommendation

- **Azure Portal**
    1. Go to the [Azure Portal](https://portal.azure.com/).
    2. Navigate to **Cognitive Services** and select your Computer Vision account.
    3. In the left menu, select **Keys and Endpoint**.
    4. Locate the **Allow access to Cognitive Services keys** or **Enable local authentication** setting.
    5. Set **Enable local authentication** to **Disabled**.
    6. Save your changes.

- **PowerShell**
    ```powershell
    # Install the Az.CognitiveServices module if not already installed
    Install-Module -Name Az.CognitiveServices

    # Disable local authentication for a Computer Vision account
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroupName>" `
      -Name "<AccountName>" `
      -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Disable local authentication for a Computer Vision account
    az cognitiveservices account update \
      --name <AccountName> \
      --resource-group <ResourceGroupName> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can deploy an Azure Policy to enforce that local authentication is disabled on all Cognitive Services accounts:
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
    - **Bulk Remediation:**  
      Use Azure Policy's **Remediation Tasks** to automatically update existing resources that do not comply.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `properties.disableLocalAuth`

<br/>

___

## Azure_ComputerVision_DP_Data_Loss_Prevention

### Display Name
Data Loss Prevention for Azure Computer Vision

### Rationale
Enabling Data Loss Prevention (DLP) for Azure Computer Vision helps ensure that sensitive data processed by the service is protected against accidental or unauthorized exposure. DLP controls are critical for organizations handling regulated or confidential information, supporting compliance with standards such as GDPR, HIPAA, and ISO 27001. Implementing DLP mitigates the risk of data breaches and helps maintain customer trust.

### Control Spec

> **Passed:**
> - Azure Computer Vision resource has DLP features enabled and configured according to organizational policy.
> - Data ingress and egress are monitored and restricted as per DLP requirements.
>
> **Failed:**
> - DLP features are not enabled or not configured on the Azure Computer Vision resource.
> - There is no monitoring or restriction of data flows, increasing the risk of data leakage.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Cognitive Services** and select your **Computer Vision** resource.
    3. Under **Security** or **Data Protection**, review available DLP settings.
    4. Enable DLP features such as data masking, logging, and access restrictions.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Example: Update Cognitive Services account with DLP settings (replace placeholders)
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroup>" `
        -Name "<AccountName>" `
        -CustomSubDomainName "<CustomDomain>" `
        -SkuName "S1" `
        -Tags @{"DLP"="Enabled"}
    ```

- **Azure CLI**
    ```bash
    # Example: Update Cognitive Services account with DLP tag (replace placeholders)
    az cognitiveservices account update \
        --resource-group <ResourceGroup> \
        --name <AccountName> \
        --set tags.DLP=Enabled
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce DLP configuration on all Cognitive Services accounts:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
              },
              {
                "field": "tags.DLP",
                "notEquals": "Enabled"
              }
            ]
          },
          "then": {
            "effect": "modify",
            "details": {
              "roleDefinitionIds": [
                "/providers/microsoft.authorization/roleDefinitions/<role-guid>"
              ],
              "operations": [
                {
                  "operation": "addOrReplace",
                  "field": "tags.DLP",
                  "value": "Enabled"
                }
              ]
            }
          }
        }
        ```
    - For bulk remediation, use Azure Policy Assignments at the subscription or management group level to ensure all new and existing Computer Vision resources have DLP enabled.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `tags.DLP`, `properties.encryption`, `properties.networkAcls`

<br/>

___

## Azure_ComputerVision_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure Computer Vision accounts

### Rationale
Restricting public network access to Azure Computer Vision accounts ensures that only trusted networks can access the resource. This reduces the attack surface, prevents unauthorized access, and helps organizations comply with regulatory requirements such as ISO 27001, SOC 2, and GDPR. Enforcing private endpoint or selected network access mitigates risks of data exfiltration and exposure to the public internet.

### Control Spec

> **Passed:**
> - The Azure Computer Vision account is configured to deny public network access (`publicNetworkAccess` is set to `Disabled`).
> - OR, the account is restricted to selected networks only, with no open public endpoints.
>
> **Failed:**
> - The Azure Computer Vision account allows public network access (`publicNetworkAccess` is set to `Enabled` or not configured).
> - The account is accessible from the public internet without network restrictions.

### Recommendation

- **Azure Portal**
    1. Navigate to **Azure Portal** > **Cognitive Services** > **Your Computer Vision account**.
    2. Select **Networking** from the left menu.
    3. Under **Public network access**, select **Disabled** to block all public access.
    4. Optionally, configure **Private endpoint connections** or **Selected networks** as required.
    5. Click **Save** to apply the changes.

- **PowerShell**
    ```powershell
    # Requires Az.CognitiveServices module
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-computer-vision-account>"
    Update-AzCognitiveServicesAccount `
      -ResourceGroupName $resourceGroupName `
      -Name $accountName `
      -PublicNetworkAccess Disabled
    ```

- **Azure CLI**
    ```bash
    az cognitiveservices account update \
      --name <your-computer-vision-account> \
      --resource-group <your-resource-group> \
      --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:** Use the built-in policy `Cognitive Services accounts should restrict public network access` to enforce this setting across your environment.
    - **Policy Assignment:** Assign the policy at the subscription or management group level for automated compliance.
    - **Bulk Remediation:** Use Azure Policy's "Remediate" feature to apply the restriction to all non-compliant resources.
    - **ARM Template Example:**
        ```json
        {
          "type": "Microsoft.CognitiveServices/accounts",
          "apiVersion": "2022-12-01",
          "name": "<your-computer-vision-account>",
          "properties": {
            "publicNetworkAccess": "Disabled"
          }
        }
        ```
    - **AzTS Remediation Script:** If using Azure Tenant Security (AzTS), refer to the AzTS remediation script for bulk disabling public network access on all Computer Vision accounts.

### Azure Policies or REST APIs used for evaluation

- **REST API:** `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
  **Properties:** `properties.publicNetworkAccess`
- **Azure Policy:** Built-in policy `Cognitive Services accounts should restrict public network access`

<br/>

___
