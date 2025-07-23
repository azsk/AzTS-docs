# AI Services

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_AIServices_Audit_Enable_Diagnostic_Settings](#azure_aiservices_audit_enable_diagnostic_settings)
- [Azure_AIServices_AuthN_Use_Managed_Service_Identity](#azure_aiservices_authn_use_managed_service_identity)
- [Azure_AIServices_DP_Data_Loss_Prevention](#azure_aiservices_dp_data_loss_prevention)
- [Azure_AIServicesMultiServiceAccount_Audit_Enable_Diagnostic_Settings](#azure_aiservicesmultiserviceaccount_audit_enable_diagnostic_settings)
- [Azure_AIServicesMultiServiceAccount_AuthN_Use_Managed_Service_Identity](#azure_aiservicesmultiserviceaccount_authn_use_managed_service_identity)
- [Azure_AIServicesMultiServiceAccount_NetSec_Restrict_Public_Network_Access](#azure_aiservicesmultiserviceaccount_netsec_restrict_public_network_access)
- [Azure_AIServices_NetSec_Restrict_Public_Network_Access](#azure_aiservices_netsec_restrict_public_network_access)
- [Azure_AIServices_AuthN_Disable_Local_Auth](#azure_aiservices_authn_disable_local_auth)
- [Azure_AIServicesMultiServiceAccount_AuthN_Disable_Local_Auth](#azure_aiservicesmultiserviceaccount_authn_disable_local_auth)

<!-- /TOC -->
<br/>

___

## Azure_AIServicesMultiServiceAccount_Audit_Enable_Diagnostic_Settings

### Display Name
Azure AI Services Multi-Service Account should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure AI Services Multi-Service Accounts ensures that all management and operational activities are logged and sent to a Log Analytics workspace, Event Hub, or Azure Storage account. This is critical for security monitoring, incident response, and compliance with regulatory requirements such as ISO 27001, SOC, and GDPR. Diagnostic logs provide visibility into resource access and usage, helping organizations detect anomalous activities and maintain an audit trail for forensic analysis.

### Control Spec

> **Passed:**
> - Diagnostic settings are enabled for the Azure AI Services Multi-Service Account resource.
> - At least one category of logs is being sent to a Log Analytics workspace, Event Hub, or Azure Storage account.
>
> **Failed:**
> - Diagnostic settings are not configured for the resource.
> - No logs are being sent to any destination.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Azure AI Services** > **Accounts**.
    3. Select the target Multi-Service Account.
    4. In the left pane, select **Diagnostic settings**.
    5. Click **+ Add diagnostic setting**.
    6. Enter a name for the setting.
    7. Select the log categories you wish to collect (e.g., AuditLogs, AllMetrics).
    8. Choose at least one destination: **Log Analytics workspace**, **Event Hub**, or **Storage account**.
    9. Click **Save**.

- **PowerShell**
    ```powershell
    # Example: Enable diagnostic settings for a Cognitive Services account
    $resourceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
    $workspaceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

    Set-AzDiagnosticSetting -ResourceId $resourceId `
        -WorkspaceId $workspaceId `
        -Name "AuditLogsToWorkspace" `
        -Enabled $true `
        -Category "AuditLogs", "AllMetrics"
    ```

- **Azure CLI**
    ```bash
    az monitor diagnostic-settings create \
      --name "AuditLogsToWorkspace" \
      --resource "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>" \
      --workspace "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>" \
      --logs '[{"category": "AuditLogs", "enabled": true}, {"category": "AllMetrics", "enabled": true}]'
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can assign the built-in policy **"Diagnostic logs in Cognitive Services should be enabled"** to enforce this control at scale.
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
    - **Bulk Remediation:**  
      Use Azure Policy's remediation tasks to deploy diagnostic settings automatically to all existing and future Cognitive Services accounts.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview`  
**Properties:**  
- `properties.logs[*].enabled`
- `properties.workspaceId`
- `properties.eventHubAuthorizationRuleId`
- `properties.storageAccountId`

<br/>

___

___

## Azure_AIServicesMultiServiceAccount_AuthN_Disable_Local_Auth

### Display Name
Disable Local Authentication for Azure AI Services Multi-Service Account

### Rationale
Disabling local authentication for Azure AI Services Multi-Service Accounts ensures that only Azure Active Directory (Azure AD) identities can access the resource. This reduces the risk of credential leakage or misuse, as local authentication keys are not subject to Azure AD's security controls, such as conditional access, multi-factor authentication, and identity protection. Enforcing Azure AD authentication aligns with best practices for securing access to sensitive AI workloads and helps organizations meet compliance requirements for identity and access management.

### Control Spec

> **Passed:**
> - Local authentication is disabled (`disableLocalAuth` property is set to `true`) for the Azure AI Services Multi-Service Account.
>
> **Failed:**
> - Local authentication is enabled (`disableLocalAuth` property is set to `false` or is not set) for the Azure AI Services Multi-Service Account.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure AI Services** resource in the Azure portal.
    2. Select your **Cognitive Services account**.
    3. In the left pane, select **Keys and Endpoint**.
    4. Locate the **Allow local authentication** setting.
    5. Set **Allow local authentication** to **Disabled**.
    6. Click **Save** to apply the changes.

- **PowerShell**
    ```powershell
    # Requires Az.CognitiveServices module
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-cognitive-services-account>"

    Update-AzCognitiveServicesAccount `
      -ResourceGroupName $resourceGroupName `
      -Name $accountName `
      -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Requires Azure CLI 2.0+
    az cognitiveservices account update \
      --name <your-cognitive-services-account> \
      --resource-group <your-resource-group> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can enforce this setting at scale using Azure Policy. Assign the built-in policy definition:
      - **Policy Name:** Cognitive Services accounts should disable local authentication
      - **Policy Definition ID:** `/providers/Microsoft.Authorization/policyDefinitions/8c7d7e3b-3b3e-4b6a-8c8f-8a6e7a7e8a7e`
      - This policy can be assigned at the subscription or management group level for automated compliance.
    - **Bulk Remediation:**  
      Use Azure Policy's **Remediation Tasks** to automatically update non-compliant resources.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`
  <br />
  **Properties Checked:**  
  `properties.disableLocalAuth`

<br/>

___

___

## Azure_AIServicesMultiServiceAccount_AuthN_Use_Managed_Service_Identity

### Display Name
Azure AI Services accounts should use Managed Identity for authentication

### Rationale
Using Managed Identities for Azure resources eliminates the need for hard-coded credentials and secrets in your code or configuration files. This enhances security by reducing the risk of credential leakage and supports compliance requirements by enforcing identity-based access control. Managed Identities also simplify credential management and rotation, aligning with best practices for secure cloud deployments.

### Control Spec

> **Passed:**
> - The Azure AI Services (Cognitive Services) multi-service account is configured to use a system-assigned or user-assigned managed identity for authentication and access to dependent Azure resources.
>
> **Failed:**
> - The Azure AI Services multi-service account is not configured to use a managed identity, and authentication relies on keys, passwords, or other static credentials.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure AI Services** (Cognitive Services) account in the Azure Portal.
    2. In the left menu, select **Identity** under the **Settings** section.
    3. Set **Status** to **On** for either **System assigned** or **User assigned** managed identity.
    4. Save your changes.
    5. Update your application code to use the managed identity for authentication instead of keys or passwords.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity for a Cognitive Services account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-cognitive-services-account>"
    Set-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -IdentityType SystemAssigned
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity for a Cognitive Services account
    az cognitiveservices account identity assign \
      --name <your-cognitive-services-account> \
      --resource-group <your-resource-group>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that all Cognitive Services accounts have managed identity enabled.
    - Example Azure Policy definition:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
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
    - For bulk remediation, use Azure CLI or PowerShell scripts to iterate through all Cognitive Services accounts and enable managed identity.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `identity.type` (should be `SystemAssigned` or `UserAssigned`)

<br/>

___

___

## Azure_AIServicesMultiServiceAccount_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict Public Network Access for Azure AI Services Multi-Service Accounts

### Rationale
Restricting public network access to Azure AI Services Multi-Service Accounts ensures that only trusted and authorized networks can access sensitive AI resources. This control reduces the attack surface, mitigates the risk of unauthorized access, and helps organizations comply with regulatory requirements such as ISO 27001, SOC 2, and GDPR by enforcing network boundary protections.

### Control Spec

> **Passed:**
> - The Azure AI Services Multi-Service Account has public network access disabled (`publicNetworkAccess` is set to `Disabled`).
> - Only selected networks or private endpoints are allowed to access the resource.
>
> **Failed:**
> - The Azure AI Services Multi-Service Account allows public network access (`publicNetworkAccess` is set to `Enabled` or not configured).
> - The resource is accessible from any public IP address.

### Recommendation

- **Azure Portal**
    1. Navigate to **Azure AI Services** in the Azure Portal.
    2. Select the target Multi-Service Account.
    3. Under **Networking**, select **Public network access**.
    4. Set **Public network access** to **Disabled**.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Replace <resourceGroupName> and <accountName> with your values
    Set-AzCognitiveServicesAccount -ResourceGroupName <resourceGroupName> `
      -Name <accountName> `
      -PublicNetworkAccess Disabled
    ```

- **Azure CLI**
    ```bash
    # Replace <resourceGroupName> and <accountName> with your values
    az cognitiveservices account update \
      --resource-group <resourceGroupName> \
      --name <accountName> \
      --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      Deploy the built-in policy:  
      `Cognitive Services accounts should restrict public network access`
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.CognitiveServices/accounts"
            },
            {
              "field": "Microsoft.CognitiveServices/accounts/publicNetworkAccess",
              "notequals": "Disabled"
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      }
      ```
    - **Bulk Remediation:**  
      Use Azure Policy's "Remediate" function to apply this setting across all accounts in a subscription or management group.
    - **ARM Template Example:**
      ```json
      {
        "type": "Microsoft.CognitiveServices/accounts",
        "apiVersion": "2023-05-01",
        "name": "[parameters('accountName')]",
        "location": "[parameters('location')]",
        "properties": {
          "publicNetworkAccess": "Disabled"
        }
      }
      ```

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`  
**Properties:** `properties.publicNetworkAccess`

<br/>

___

___

## Azure_AIServices_Audit_Enable_Diagnostic_Settings

### Display Name
Azure AI Services should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure AI Services (Cognitive Services) ensures that resource-level logs and metrics are collected and exported to a Log Analytics workspace, Event Hub, or Azure Storage account. This is critical for monitoring, auditing, and investigating security incidents, as well as meeting compliance requirements such as ISO 27001, SOC, and GDPR. Without diagnostic logging, it is difficult to track access patterns, detect anomalies, or perform forensic analysis in the event of a security breach.

### Control Spec

> **Passed:**
> - The Azure AI Services (Cognitive Services) account has at least one diagnostic setting configured to export logs and/or metrics to a supported destination (Log Analytics, Event Hub, or Storage Account).
>
> **Failed:**
> - The Azure AI Services (Cognitive Services) account does not have any diagnostic settings enabled.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Cognitive Services** and select the target resource.
    3. In the left pane, select **Diagnostic settings** under the **Monitoring** section.
    4. Click **+ Add diagnostic setting**.
    5. Provide a name for the setting.
    6. Select the logs and metrics you want to collect.
    7. Choose one or more destinations: **Log Analytics workspace**, **Event Hub**, or **Storage account**.
    8. Click **Save**.

- **PowerShell**
    ```powershell
    # Install the Az module if not already installed
    Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

    # Set variables
    $resourceGroup = "<ResourceGroupName>"
    $accountName = "<CognitiveServicesAccountName>"
    $workspaceId = "<LogAnalyticsWorkspaceResourceId>"

    # Create diagnostic setting
    Set-AzDiagnosticSetting -ResourceId "/subscriptions/<subscription-id>/resourceGroups/$resourceGroup/providers/Microsoft.CognitiveServices/accounts/$accountName" `
        -WorkspaceId $workspaceId `
        -Name "AuditLogsAndMetrics" `
        -Enabled $true `
        -Category "AllLogs","AllMetrics"
    ```

- **Azure CLI**
    ```bash
    # Set variables
    RESOURCE_GROUP="<ResourceGroupName>"
    ACCOUNT_NAME="<CognitiveServicesAccountName>"
    WORKSPACE_ID="<LogAnalyticsWorkspaceResourceId>"

    # Create diagnostic setting
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscription-id>/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.CognitiveServices/accounts/$ACCOUNT_NAME" \
      --name "AuditLogsAndMetrics" \
      --workspace $WORKSPACE_ID \
      --logs '[{"category": "AllLogs", "enabled": true}]' \
      --metrics '[{"category": "AllMetrics", "enabled": true}]'
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      Use the built-in policy definition:  
      `Audit diagnostic setting` for Microsoft.CognitiveServices/accounts  
      Policy ID: `/providers/Microsoft.Authorization/policyDefinitions/0a15c9a5-5a5c-4d0d-8b6e-5f1b3b2b1a3e`
    - **Bulk Remediation:**  
      Assign the above Azure Policy at the subscription or management group level to audit and enforce diagnostic settings across all Cognitive Services accounts.
    - **ARM Template Example:**
      ```json
      {
        "type": "Microsoft.Insights/diagnosticSettings",
        "apiVersion": "2021-05-01-preview",
        "name": "AuditLogsAndMetrics",
        "dependsOn": [
          "[resourceId('Microsoft.CognitiveServices/accounts', parameters('accountName'))]"
        ],
        "properties": {
          "workspaceId": "<LogAnalyticsWorkspaceResourceId>",
          "logs": [
            {
              "category": "AllLogs",
              "enabled": true
            }
          ],
          "metrics": [
            {
              "category": "AllMetrics",
              "enabled": true
            }
          ]
        }
      }
      ```

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview`  
  **Properties:**  
  - `logs`
  - `metrics`
  - `workspaceId`
  - `eventHubAuthorizationRuleId`
  - `storageAccountId`

<br/>

___

___

## Azure_AIServices_AuthN_Disable_Local_Auth

### Display Name
Disable Local Authentication for Azure AI Services

### Rationale

Disabling local authentication methods (such as account keys) for Azure AI Services ensures that only Azure Active Directory (Azure AD) identities can be used to access the resource. This enhances security by enforcing identity-based access control, supporting conditional access policies, and enabling better monitoring and auditing. Relying solely on Azure AD authentication reduces the risk of credential leakage and unauthorized access, aligning with security best practices and compliance requirements such as ISO 27001 and SOC 2.

### Control Spec

> **Passed:**
> - The Azure AI Services resource has local authentication (account keys) disabled (`disableLocalAuth` property is set to `true`). Only Azure AD authentication is enabled.
>
> **Failed:**
> - The Azure AI Services resource has local authentication (account keys) enabled (`disableLocalAuth` property is `false` or not set). This allows access using account keys in addition to Azure AD identities.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure AI Services** resource (Cognitive Services account) in the Azure Portal.
    2. Under **Resource Management**, select **Keys and Endpoint**.
    3. Locate the **Local authentication** setting.
    4. Set **Local authentication** to **Disabled**.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Requires Az.CognitiveServices module
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-cognitive-services-account>"

    Update-AzCognitiveServicesAccount `
        -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Requires Azure CLI 2.7.0+ and Cognitive Services extension
    az cognitiveservices account update \
      --name <your-cognitive-services-account> \
      --resource-group <your-resource-group> \
      --disable-local-auth true
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can assign the built-in Azure Policy **[Cognitive Services accounts should disable local authentication](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDefinitionDetailsBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F0a15c9a8-7c6b-4c7c-9c7a-3e7c6b7c9a8a)** to enforce this setting across your subscriptions.
    - **Bulk Remediation:**  
      Use Azure Policy's **Remediation Tasks** to automatically update non-compliant resources.
    - **ARM Template Example:**
      ```json
      {
        "type": "Microsoft.CognitiveServices/accounts",
        "apiVersion": "2022-12-01",
        "name": "<your-cognitive-services-account>",
        "properties": {
          "disableLocalAuth": true
        }
      }
      ```

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
  **Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_AIServices_AuthN_Use_Managed_Service_Identity

### Display Name
Azure AI Services should use Managed Service Identity (MSI) for authentication

### Rationale
Enabling Managed Service Identity (MSI) for Azure AI Services ensures that applications authenticate securely to Azure resources without the need to manage credentials in code or configuration files. This reduces the risk of credential leakage, simplifies identity management, and aligns with best practices for secure application development. Using MSI helps organizations meet compliance requirements for secure authentication and access control, such as those outlined in ISO 27001, SOC 2, and Azure CIS benchmarks.

### Control Spec

> **Passed:**
> - The Azure AI Service resource (Microsoft.CognitiveServices/accounts) has Managed Identity (either system-assigned or user-assigned) enabled.
>
> **Failed:**
> - The Azure AI Service resource does not have Managed Identity enabled, or the identity is not configured for authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Cognitive Services** and select your AI Service resource.
    3. In the left menu, select **Identity** under the **Settings** section.
    4. Set **Status** to **On** for either **System assigned** or **User assigned** managed identity.
    5. Click **Save** to apply changes.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity for an Azure AI Service account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-ai-service-account>"
    Set-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName -Name $accountName -IdentityType SystemAssigned
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity for an Azure AI Service account
    az cognitiveservices account identity assign --name <your-ai-service-account> --resource-group <your-resource-group>
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      Deploy the built-in policy **[Cognitive Services accounts should use managed identities](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDefinitionDetailsBlade/definitionId/...)** to enforce MSI usage across all Cognitive Services resources.
    - **Bulk Remediation:**  
      Use Azure Policy's "Remediate" function to assign managed identities to all non-compliant resources at scale.
    - **ARM Template Example:**
      ```json
      {
        "type": "Microsoft.CognitiveServices/accounts",
        "apiVersion": "2022-12-01",
        "name": "<your-ai-service-account>",
        "identity": {
          "type": "SystemAssigned"
        },
        ...
      }
      ```
    - **AzTS Remediation Script:**  
      If using Azure Tenant Security (AzTS), run the provided remediation script to enable managed identities on all Cognitive Services accounts in the tenant.

### Azure Policies or REST APIs used for evaluation

- **REST API:** `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
  **Properties:**  
  - `identity.type` should be set to `SystemAssigned`, `UserAssigned`, or `SystemAssigned, UserAssigned`.

<br/>

___

___

## Azure_AIServices_DP_Data_Loss_Prevention

### Display Name
Azure AI Services Data Loss Prevention (DLP) Must Be Enabled

### Rationale
Enabling Data Loss Prevention (DLP) for Azure AI Services helps protect sensitive data from accidental exposure or leakage. DLP policies enforce restrictions on data input and output, ensuring that personally identifiable information (PII), financial data, or other confidential content is not inadvertently processed or returned by AI models. This control supports compliance with regulatory requirements such as GDPR, HIPAA, and other data protection standards.

### Control Spec

> **Passed:**  
> DLP is enabled on the Azure AI Services resource, enforcing data protection policies for input and output data.
>
> **Failed:**  
> DLP is not enabled, or the resource is missing required DLP configurations, increasing the risk of data leakage.

### Recommendation

- **Azure Portal**
    1. Navigate to **Azure Portal**.
    2. Go to **Cognitive Services** and select your resource.
    3. Under **Settings**, select **Data Loss Prevention**.
    4. Enable DLP and configure the required policies (e.g., block PII, restrict data export).
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Replace <resourceGroupName> and <accountName> with your values
    Set-AzCognitiveServicesAccount -ResourceGroupName <resourceGroupName> `
      -Name <accountName> `
      -CustomSubDomainName <subdomain> `
      -Properties @{ "dataLossPrevention" = @{ "enabled" = $true } }
    ```

- **Azure CLI**
    ```bash
    # Replace <resource-group> and <n> with your values
    az cognitiveservices account update \
      --resource-group <resource-group> \
      --name <n> \
      --set properties.dataLossPrevention.enabled=true
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
              },
              {
                "field": "Microsoft.CognitiveServices/accounts/dataLossPrevention.enabled",
                "notEquals": "true"
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
                  "field": "Microsoft.CognitiveServices/accounts/dataLossPrevention.enabled",
                  "value": "true"
                }
              ]
            }
          }
        }
        ```
    - **Bulk Remediation:**  
      Use Azure Policy Assignments at the subscription or management group level to enforce DLP across all Cognitive Services accounts.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `properties.dataLossPrevention.enabled`

<br/>

___

___

## Azure_AIServices_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure AI Services accounts

### Rationale
Restricting public network access to Azure AI Services (Cognitive Services) accounts ensures that only trusted networks can access the resource. This reduces the attack surface by preventing unauthorized or anonymous access from the public internet, thereby helping to protect sensitive data and comply with regulatory requirements such as ISO 27001, SOC 2, and GDPR.

### Control Spec

> **Passed:**
> - The Azure AI Services account has public network access disabled (`publicNetworkAccess` property set to `Disabled`).
> - Only trusted subnets or private endpoints are allowed.
>
> **Failed:**
> - The Azure AI Services account allows public network access (`publicNetworkAccess` property set to `Enabled` or not set).
> - The resource is accessible from the public internet.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure portal**.
    2. Go to **Cognitive Services** and select the target account.
    3. In the left pane, select **Networking**.
    4. Under **Public network access**, select **Disabled**.
    5. Optionally, configure **Private endpoint connections** or specify trusted virtual networks/subnets.
    6. Click **Save** to apply the changes.

- **PowerShell**
    ```powershell
    # Install the Az module if not already installed
    Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

    # Set public network access to Disabled
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroupName>" `
      -Name "<AccountName>" `
      -PublicNetworkAccess Disabled
    ```

- **Azure CLI**
    ```bash
    # Set public network access to Disabled
    az cognitiveservices account update \
      --name <AccountName> \
      --resource-group <ResourceGroupName> \
      --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition**: Deploy or assign the built-in policy `Cognitive Services accounts should restrict public network access` to enforce this setting across your environment.
    - **Bulk Remediation**: Use Azure Policy's remediation tasks to automatically update non-compliant resources.
    - **ARM Template Example**:
        ```json
        {
          "type": "Microsoft.CognitiveServices/accounts",
          "apiVersion": "2022-12-01",
          "name": "[parameters('accountName')]",
          "properties": {
            "publicNetworkAccess": "Disabled"
          }
        }
        ```
    - **AzTS Remediation Script** (if referenced in your environment):
        - Use AzTS bulk remediation scripts to identify and update all non-compliant Azure AI Services accounts.

### Azure Policies or REST APIs used for evaluation

- **REST API:** `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
**Properties:** `publicNetworkAccess`

<br/>

___

___
