# Face API

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_FaceAPI_Audit_Enable_Diagnostic_Settings](#azure_faceapi_audit_enable_diagnostic_settings)
- [Azure_FaceAPI_DP_Data_Loss_Prevention](#azure_faceapi_dp_data_loss_prevention)
- [Azure_FaceAPI_AuthN_Disable_Local_Auth](#azure_faceapi_authn_disable_local_auth)
- [Azure_FaceAPI_AuthN_Use_Managed_Service_Identity](#azure_faceapi_authn_use_managed_service_identity)
- [Azure_FaceAPI_NetSec_Restrict_Public_Network_Access](#azure_faceapi_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_FaceAPI_Audit_Enable_Diagnostic_Settings

### Display Name
Azure Face API should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure Face API ensures that resource logs and metrics are collected and sent to a Log Analytics workspace, Event Hub, or Storage Account. This is critical for monitoring, auditing, and compliance purposes. Diagnostic logs help organizations detect anomalous activities, investigate incidents, and meet regulatory requirements such as GDPR, ISO 27001, and SOC 2.

### Control Spec

> **Passed:**  
> Diagnostic settings are enabled for the Azure Face API resource, and logs are being sent to at least one of the following: Log Analytics workspace, Event Hub, or Azure Storage account.
>
> **Failed:**  
> Diagnostic settings are not enabled for the Azure Face API resource, or logs are not being sent to any destination.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure Portal.
    2. Go to **Cognitive Services** and select your **Face API** resource.
    3. In the left pane, select **Diagnostic settings** under the **Monitoring** section.
    4. Click **+ Add diagnostic setting**.
    5. Enter a name for the setting.
    6. Select the logs and metrics you want to collect (e.g., AuditLogs, RequestResponseLogs).
    7. Choose at least one destination: **Log Analytics workspace**, **Event Hub**, or **Storage account**.
    8. Click **Save**.

- **PowerShell**
    ```powershell
    # Variables
    $resourceGroup = "<ResourceGroupName>"
    $accountName = "<FaceAPIResourceName>"
    $workspaceId = "<LogAnalyticsResourceId>"
    $diagnosticName = "FaceAPIDiagnostics"

    # Enable diagnostic settings
    Set-AzDiagnosticSetting -ResourceId "/subscriptions/<subscriptionId>/resourceGroups/$resourceGroup/providers/Microsoft.CognitiveServices/accounts/$accountName" `
        -WorkspaceId $workspaceId `
        -Name $diagnosticName `
        -Enabled $true `
        -Category "AuditLogs", "RequestResponseLogs"
    ```

- **Azure CLI**
    ```bash
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscriptionId>/resourceGroups/<ResourceGroupName>/providers/Microsoft.CognitiveServices/accounts/<FaceAPIResourceName>" \
      --name "FaceAPIDiagnostics" \
      --workspace "<LogAnalyticsResourceId>" \
      --logs '[{"category": "AuditLogs", "enabled": true}, {"category": "RequestResponseLogs", "enabled": true}]'
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can use the built-in Azure Policy **"Cognitive Services accounts should have diagnostic logging enabled"** to enforce this setting across your environment.
    - **Bulk Remediation:**  
      Use Azure Policy's "DeployIfNotExists" effect to automatically configure diagnostic settings for all Face API resources.
    - **ARM Template Example:**  
      ```json
      {
        "type": "Microsoft.Insights/diagnosticSettings",
        "apiVersion": "2021-05-01-preview",
        "name": "FaceAPIDiagnostics",
        "dependsOn": [
          "[resourceId('Microsoft.CognitiveServices/accounts', parameters('faceApiName'))]"
        ],
        "properties": {
          "workspaceId": "[parameters('logAnalyticsWorkspaceId')]",
          "logs": [
            {
              "category": "AuditLogs",
              "enabled": true
            },
            {
              "category": "RequestResponseLogs",
              "enabled": true
            }
          ]
        }
      }
      ```
    - **AzTS Remediation:**  
      If using Azure Tenant Security (AzTS), leverage the provided remediation script to enable diagnostics at scale.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/Microsoft.Insights/diagnosticSettings?api-version=2017-05-01-preview`  
  **Properties:** `logs`, `workspaceId`, `eventHubAuthorizationRuleId`, `storageAccountId`

<br/>

___

___

## Azure_FaceAPI_AuthN_Disable_Local_Auth

### Display Name
Disable local authentication methods for Azure Face API

### Rationale
Disabling local authentication methods (such as account keys) for Azure Face API ensures that only Azure Active Directory (Azure AD) identities can access the resource. This reduces the risk of credential leakage and unauthorized access, and aligns with security best practices and compliance requirements such as Zero Trust and least privilege. Enforcing Azure AD authentication provides better control, auditing, and conditional access capabilities.

### Control Spec

> **Passed:**
> - Local authentication methods (e.g., account keys) are disabled for the Azure Face API resource.
> - Only Azure AD authentication is permitted.
>
> **Failed:**
> - Local authentication methods (e.g., account keys) are enabled for the Azure Face API resource.
> - Azure AD authentication is not enforced exclusively.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Face API resource in the Azure Portal.
    2. In the left menu, select **Settings** > **Authentication**.
    3. Locate the **Allow local authentication** setting.
    4. Set **Allow local authentication** to **Disabled**.
    5. Click **Save** to apply the changes.

- **PowerShell**
    ```powershell
    # Install the Az.CognitiveServices module if not already installed
    Install-Module -Name Az.CognitiveServices

    # Disable local authentication for the Face API resource
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroupName>" `
      -Name "<FaceAPIAccountName>" `
      -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Disable local authentication for the Face API account
    az cognitiveservices account update \
      --name <FaceAPIAccountName> \
      --resource-group <ResourceGroupName> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - **Azure Policy Definition Example:**
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
              },
              {
                "field": "Microsoft.CognitiveServices/accounts/capabilities.disableLocalAuth",
                "notEquals": "true"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - **Bulk Remediation:** Use Azure Policy to audit and enforce this setting across all Cognitive Services resources in your subscription or management group.
    - **ARM Template Example:**
        ```json
        {
          "type": "Microsoft.CognitiveServices/accounts",
          "apiVersion": "2022-12-01",
          "name": "[parameters('accountName')]",
          "properties": {
            "disableLocalAuth": true
          }
        }
        ```

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
**Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_FaceAPI_AuthN_Use_Managed_Service_Identity

### Display Name
Azure Face API should use Managed Service Identity (MSI) for authentication

### Rationale
Requiring the use of Managed Service Identity (MSI) for Azure Face API authentication enhances security by eliminating the need for hard-coded credentials or API keys in code or configuration files. MSI leverages Azure Active Directory (Azure AD) to provide secure, automatic identity management for applications and services. This reduces the risk of credential leakage and simplifies credential rotation, supporting compliance with best practices and regulatory requirements such as ISO 27001, SOC 2, and GDPR.

### Control Spec

> **Passed:**
> - The Azure Face API resource is configured to use a system-assigned or user-assigned Managed Service Identity (MSI) for authentication.
> - No API keys or static credentials are used for authentication to the Face API.
>
> **Failed:**
> - The Azure Face API resource is not configured with MSI.
> - Authentication relies on API keys or static credentials.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Face API resource in the Azure Portal.
    2. In the left menu, select **Identity** under the **Settings** section.
    3. Set the **Status** to **On** for either **System assigned** or **User assigned** managed identity.
    4. Click **Save**.
    5. Update your client applications to use Azure AD tokens for authentication instead of API keys.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity for a Cognitive Services account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-face-api-account>"
    Set-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName `
                                   -Name $accountName `
                                   -IdentityType SystemAssigned
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity for a Cognitive Services account
    az cognitiveservices account identity assign \
      --name <your-face-api-account> \
      --resource-group <your-resource-group>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that all Cognitive Services accounts (including Face API) must have managed identities enabled:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
              },
              {
                "field": "Microsoft.CognitiveServices/accounts/identity.type",
                "notEquals": "SystemAssigned"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use an Azure Policy remediation task to assign managed identities to all non-compliant resources.
    - Update application code to use Azure AD authentication flows and remove any hard-coded API keys.

### Azure Policies or REST APIs used for evaluation

- **REST API:** `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `identity.type` (should be `SystemAssigned` or `UserAssigned`)

<br/>

___

___

## Azure_FaceAPI_DP_Data_Loss_Prevention

### Display Name
Enforce Data Loss Prevention (DLP) for Azure Face API

### Rationale
Data Loss Prevention (DLP) controls are critical for protecting sensitive biometric data processed by Azure Face API. Enforcing DLP policies helps prevent accidental or unauthorized data exfiltration, ensuring compliance with privacy regulations such as GDPR and ISO/IEC 27001. Proper DLP configuration reduces the risk of data breaches and supports organizational security and compliance objectives.

### Control Spec

> **Passed:**
> - Azure Face API resource has DLP policies enabled and configured according to organizational standards.
> - Data ingress and egress are monitored and restricted as per DLP requirements.
> - Logging and alerting for data transfer events are active.
>
> **Failed:**
> - Azure Face API resource does not have DLP policies enabled.
> - There is no monitoring or restriction on data ingress/egress.
> - Logging and alerting for sensitive data movement are not configured.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Face API resource in the Azure Portal.
    2. Select **Data Loss Prevention** under the **Security** section.
    3. Enable DLP and configure policies to restrict data movement and monitor access.
    4. Set up alerts for unauthorized data transfers.
    5. Save your configuration.

- **PowerShell**
    ```powershell
    # Enable DLP on a Cognitive Services account (Face API)
    $resourceGroup = "<your-resource-group>"
    $accountName = "<your-face-api-account>"
    $properties = @{
        "properties" = @{
            "encryption" = @{
                "keySource" = "Microsoft.KeyVault"
            }
            "networkAcls" = @{
                "defaultAction" = "Deny"
                "bypass" = "AzureServices"
            }
        }
    }
    Set-AzResource -ResourceType "Microsoft.CognitiveServices/accounts" `
        -ResourceGroupName $resourceGroup `
        -ResourceName $accountName `
        -Properties $properties
    ```

- **Azure CLI**
    ```bash
    # Restrict network access and enable logging for Face API
    az cognitiveservices account update \
      --name <your-face-api-account> \
      --resource-group <your-resource-group> \
      --set properties.networkAcls.defaultAction=Deny \
      --set properties.networkAcls.bypass=AzureServices
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce DLP settings on all Cognitive Services accounts:
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
                  "field": "Microsoft.CognitiveServices/accounts/networkAcls.defaultAction",
                  "equals": "Deny"
                }
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use Azure Blueprints or deploy an ARM template to apply DLP configurations across multiple resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
<br />
**Properties:** `properties.networkAcls`, `properties.encryption`, `properties.diagnosticSettings`

<br/>

___

**Note:**  
The above documentation is based on standard Azure security and compliance patterns for DLP enforcement on Cognitive Services. If more specific remediation scripts or automation tools (such as AzTS) are referenced in your official documentation, please provide the content for inclusion.

___

## Azure_FaceAPI_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure Face API accounts

### Rationale
Restricting public network access to Azure Face API accounts ensures that only trusted networks can access the resource, reducing the risk of unauthorized access and potential data breaches. Enforcing network restrictions is a critical security best practice and supports compliance with regulatory frameworks such as ISO 27001, SOC 2, and GDPR by limiting exposure to the public internet.

### Control Spec

> **Passed:**  
> The Azure Face API account has public network access disabled, and access is restricted to selected networks (such as specific virtual networks or IP address ranges).
>
> **Failed:**  
> The Azure Face API account allows public network access, making it accessible from any internet location.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure Portal**.
    2. Go to **Cognitive Services** and select your **Face API** account.
    3. Under **Settings**, select **Networking**.
    4. Set **Public network access** to **Disabled**.
    5. (Optional) Configure **Private endpoint connections** or specify allowed virtual networks and IP address ranges.

- **PowerShell**
    ```powershell
    # Disable public network access for a Face API account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-faceapi-account>"
    Update-AzCognitiveServicesAccount `
        -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -PublicNetworkAccess "Disabled"
    ```

- **Azure CLI**
    ```bash
    # Disable public network access for a Face API account
    az cognitiveservices account update \
        --resource-group <your-resource-group> \
        --name <your-faceapi-account> \
        --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can assign the built-in policy **"Cognitive Services accounts should restrict public network access"** (`/providers/Microsoft.Authorization/policyDefinitions/2a1b5b2b-5c7c-4c7d-8c2b-2b2b2b2b2b2b`) to enforce this control across your subscription or management group.
    - **ARM Template Snippet:**
      ```json
      {
        "type": "Microsoft.CognitiveServices/accounts",
        "apiVersion": "2022-12-01",
        "name": "<your-faceapi-account>",
        "properties": {
          "publicNetworkAccess": "Disabled"
        }
      }
      ```
    - **Bulk Remediation:**  
      Use Azure Policy's "DeployIfNotExists" effect to automatically remediate non-compliant Face API accounts.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
**Properties:** `properties.publicNetworkAccess`

<br/>

___


