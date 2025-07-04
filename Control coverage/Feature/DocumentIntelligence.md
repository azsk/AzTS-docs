# Document Intelligence

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_DocumentIntelligence_AuthN_Disable_Local_Auth](#azure_documentintelligence_authn_disable_local_auth)
- [Azure_DocumentIntelligence_AuthN_Use_Managed_Service_Identity](#azure_documentintelligence_authn_use_managed_service_identity)
- [Azure_DocumentIntelligence_DP_Data_Loss_Prevention](#azure_documentintelligence_dp_data_loss_prevention)
- [Azure_DocumentIntelligence_NetSec_Restrict_Public_Network_Access](#azure_documentintelligence_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_DocumentIntelligence_AuthN_Disable_Local_Auth

### Display Name
Disable local authentication methods for Azure Document Intelligence

### Rationale
Disabling local authentication (such as account keys) for Azure Document Intelligence ensures that only Azure Active Directory (Azure AD) identities can access the resource. This enhances security by enforcing modern authentication protocols, enabling better access control, auditability, and compliance with organizational and regulatory requirements. Local authentication methods are more susceptible to credential leakage and do not provide the same level of security controls as Azure AD.

### Control Spec

> **Passed:**
> - Local authentication (API keys) is disabled for the Azure Document Intelligence resource.
> - Only Azure AD-based authentication is permitted.
>
> **Failed:**
> - Local authentication (API keys) is enabled for the Azure Document Intelligence resource.
> - The resource allows access using account keys.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Document Intelligence (Cognitive Services) resource.
    2. In the left menu, select **Security**.
    3. Under **Authentication**, locate the **Allow local authentication** setting.
    4. Set **Allow local authentication** to **Disabled**.
    5. Click **Save** to apply the changes.

- **PowerShell**
    ```powershell
    # Install the Az.CognitiveServices module if not already installed
    Install-Module -Name Az.CognitiveServices

    # Disable local authentication for a specific Cognitive Services account
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroupName>" `
      -Name "<AccountName>" `
      -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Disable local authentication for a Cognitive Services account
    az cognitiveservices account update \
      --name <AccountName> \
      --resource-group <ResourceGroupName> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that local authentication is disabled:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
              },
              {
                "field": "Microsoft.CognitiveServices/accounts/disableLocalAuth",
                "notEquals": "true"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - Bulk remediation can be performed using PowerShell or Azure CLI scripts across multiple resources.
    - Azure Policy can be assigned at the subscription or management group level for tenant-wide enforcement.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`
  <br />
  **Properties:** `properties.disableLocalAuth` (should be set to `true`)

<br/>

___

___

## Azure_DocumentIntelligence_AuthN_Use_Managed_Service_Identity

### Display Name
Azure Document Intelligence accounts should use Managed Service Identity (MSI) for authentication

### Rationale
Enabling Managed Service Identity (MSI) for Azure Document Intelligence accounts ensures that applications can authenticate securely to Azure services without managing credentials in code or configuration. This reduces the risk of credential leakage, simplifies credential management, and aligns with best practices for secure cloud application development. Using MSI also helps organizations meet compliance requirements for secure authentication and access control.

### Control Spec

> **Passed:**
> The Azure Document Intelligence (Cognitive Services) account is configured to use Managed Service Identity (MSI) for authentication.
>
> **Failed:**
> The Azure Document Intelligence (Cognitive Services) account is not configured to use Managed Service Identity (MSI), or authentication relies on keys or other insecure methods.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Document Intelligence (Cognitive Services) account in the Azure Portal.
    2. In the left menu, select **Identity** under the **Settings** section.
    3. Set the **Status** to **On** to enable the system-assigned managed identity.
    4. Save your changes.
    5. Update your application code to use Azure AD authentication via the managed identity instead of access keys.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity for a Cognitive Services account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-cognitiveservices-account>"
    Set-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName -Name $accountName -IdentityType SystemAssigned
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity for a Cognitive Services account
    az cognitiveservices account identity assign --name <your-cognitiveservices-account> --resource-group <your-resource-group>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that all Cognitive Services accounts have managed identity enabled:
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
    - For bulk remediation, use PowerShell or Azure CLI scripts to iterate over all Cognitive Services accounts and enable MSI.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `identity.type` (should be set to `SystemAssigned`)

<br/>

___

___

## Azure_DocumentIntelligence_DP_Data_Loss_Prevention

### Display Name
Data Loss Prevention for Azure Document Intelligence

### Rationale
Implementing Data Loss Prevention (DLP) controls for Azure Document Intelligence ensures that sensitive data processed by the service is protected against unauthorized access, accidental exposure, or exfiltration. Enabling DLP helps organizations comply with regulatory requirements (such as GDPR, HIPAA, and ISO 27001), reduces the risk of data breaches, and enforces best practices for data security within AI-powered document processing workflows.

### Control Spec

> **Passed:**
> - Data Loss Prevention features are enabled and properly configured for the Azure Document Intelligence resource.
> - Policies are in place to monitor, detect, and prevent unauthorized sharing or transfer of sensitive data.
>
> **Failed:**
> - DLP features are not enabled for the Azure Document Intelligence resource.
> - No policies exist to monitor or restrict the movement of sensitive data processed by the service.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Document Intelligence (Cognitive Services) resource.
    2. In the left menu, select **Security** or **Data Protection** (if available).
    3. Review and enable Data Loss Prevention (DLP) settings.
    4. Configure DLP policies to monitor and restrict sensitive data movement.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Example: Enable DLP settings for a Cognitive Services account
    # (Replace with actual parameters and property names as available)
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroup>" `
      -Name "<AccountName>" `
      -CustomProperties @{"dataLossPreventionEnabled"="true"}
    ```

- **Azure CLI**
    ```bash
    # Example: Update Cognitive Services account with DLP enabled
    az cognitiveservices account update \
      --name <AccountName> \
      --resource-group <ResourceGroup> \
      --set properties.dataLossPreventionEnabled=true
    ```

- **Automation/Remediation**
    - No specific automation scripts, Azure Policy definitions, or ARM templates were referenced in the provided source content.
    - For bulk or tenant-wide configuration, consider using Azure Policy to enforce DLP settings across all Cognitive Services accounts:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.CognitiveServices/accounts"
              }
            ]
          },
          "then": {
            "effect": "auditIfNotExists",
            "details": {
              "type": "Microsoft.CognitiveServices/accounts",
              "name": "default",
              "existenceCondition": {
                "field": "Microsoft.CognitiveServices/accounts/properties.dataLossPreventionEnabled",
                "equals": "true"
              }
            }
          }
        }
        ```
    - Use Azure Policy assignments to enforce DLP settings at scale.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `properties.dataLossPreventionEnabled`

<br/>

___

**Note:**  
The provided source content did not contain specific remediation scripts, automation tools, or detailed configuration steps. The above documentation follows Azure best practices and standard remediation approaches for enabling and enforcing Data Loss Prevention in Azure Document Intelligence. If more detailed remediation or automation steps are provided in future documentation, update this section accordingly.

___

## Azure_DocumentIntelligence_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure Document Intelligence accounts

### Rationale
Restricting public network access to Azure Document Intelligence (formerly Form Recognizer) accounts helps prevent unauthorized access and data exfiltration by ensuring that only trusted, private endpoints or selected networks can interact with the resource. This control is critical for compliance with security standards such as ISO 27001, SOC 2, and GDPR, and reduces the attack surface by eliminating exposure to the public internet.

### Control Spec

> **Passed:**
> - The Azure Document Intelligence account is configured to deny public network access (`publicNetworkAccess` is set to `Disabled`).
> - Only private endpoints or selected networks are allowed.
>
> **Failed:**
> - The Azure Document Intelligence account allows public network access (`publicNetworkAccess` is set to `Enabled` or not set).
> - The resource is accessible from the public internet.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Document Intelligence (Form Recognizer) account in the Azure Portal.
    2. In the left menu, select **Networking**.
    3. Under **Public network access**, select **Deny** to block all public access.
    4. Optionally, configure **Private endpoint connections** or **Selected networks** as needed.
    5. Click **Save** to apply the changes.

- **PowerShell**
    ```powershell
    # Requires Az.CognitiveServices module
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-form-recognizer-account>"
    Update-AzCognitiveServicesAccount `
        -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -PublicNetworkAccess Disabled
    ```

- **Azure CLI**
    ```bash
    # Requires Azure CLI 2.19.1+ and extension for cognitiveservices
    az cognitiveservices account update \
        --name <your-form-recognizer-account> \
        --resource-group <your-resource-group> \
        --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can assign the built-in policy **"Cognitive Services accounts should restrict public network access"** (`/providers/Microsoft.Authorization/policyDefinitions/0a15c9c6-8b61-4a9a-8c7d-8b4f3b7e2c4b`) to enforce this setting across your subscriptions.
    - **ARM Template Snippet:**
        ```json
        {
          "type": "Microsoft.CognitiveServices/accounts",
          "apiVersion": "2022-12-01",
          "name": "<your-form-recognizer-account>",
          "properties": {
            "publicNetworkAccess": "Disabled"
          }
        }
        ```
    - **Bulk Remediation:**  
      Use Azure Policy's "DeployIfNotExists" effect to automatically remediate non-compliant resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`  
**Properties:** `properties.publicNetworkAccess`

<br/>

___


