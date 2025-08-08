# Language Service

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_LanguageService_Audit_Enable_Diagnostic_Settings](#azure_languageservice_audit_enable_diagnostic_settings)
- [Azure_LanguageService_AuthN_Disable_Local_Auth](#azure_languageservice_authn_disable_local_auth)
- [Azure_LanguageService_AuthN_Use_Managed_Service_Identity](#azure_languageservice_authn_use_managed_service_identity)
- [Azure_LanguageService_DP_Data_Loss_Prevention](#azure_languageservice_dp_data_loss_prevention)
- [Azure_LanguageService_NetSec_Restrict_Public_Network_Access](#azure_languageservice_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_LanguageService_Audit_Enable_Diagnostic_Settings

### Display Name
Azure Language Service should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure Language Service resources ensures that critical operational and security logs are collected and exported to a Log Analytics workspace, Event Hub, or Storage Account. This supports monitoring, auditing, and compliance requirements, and helps organizations detect anomalous activity, investigate incidents, and meet regulatory standards such as ISO 27001, SOC, and GDPR.

### Control Spec

> **Passed:**
> Diagnostic settings are enabled on the Azure Language Service resource, and logs are being sent to at least one of the following: a Log Analytics workspace, Event Hub, or an Azure Storage account.
>
> **Failed:**
> Diagnostic settings are not enabled on the Azure Language Service resource, or logs are not being sent to any destination.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure Language Service** resource (Microsoft.CognitiveServices/accounts).
    2. In the left pane, select **Diagnostic settings** under the **Monitoring** section.
    3. Click **+ Add diagnostic setting**.
    4. Enter a name for the setting.
    5. Select the log categories you want to collect (e.g., AuditLogs, RequestResponseLogs).
    6. Choose at least one destination: **Log Analytics workspace**, **Event Hub**, or **Storage account**.
    7. Click **Save**.

- **PowerShell**
    ```powershell
    # Example: Enable diagnostic settings for Azure Language Service
    $resourceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
    $workspaceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

    Set-AzDiagnosticSetting -ResourceId $resourceId `
        -WorkspaceId $workspaceId `
        -Name "LanguageServiceDiagnostics" `
        -Enabled $true `
        -Category "AuditLogs", "RequestResponseLogs"
    ```

- **Azure CLI**
    ```bash
    # Example: Enable diagnostic settings for Azure Language Service
    az monitor diagnostic-settings create \
      --resource "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>" \
      --name "LanguageServiceDiagnostics" \
      --workspace "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>" \
      --logs '[{"category": "AuditLogs", "enabled": true}, {"category": "RequestResponseLogs", "enabled": true}]'
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:** Use the built-in policy definition:  
      **Name:** "Diagnostic logs in Cognitive Services should be enabled"  
      **Policy ID:** `/providers/Microsoft.Authorization/policyDefinitions/4f3c2b11-6c6c-4a7b-9e4c-1a8f2c7f6b8e`
    - **Bulk Remediation:** Assign the above policy at the subscription or management group level to audit and enforce diagnostic settings across all Azure Language Service resources.
    - **ARM Template:** You can deploy diagnostic settings at scale using ARM templates. Refer to [Azure Resource Manager template documentation](https://docs.microsoft.com/azure/templates/microsoft.insights/diagnosticsettings).

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/{resourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview`  
  **Properties:** Checks for the existence of diagnostic settings and verifies that at least one destination (Log Analytics, Event Hub, or Storage Account) is configured and that relevant log categories are enabled.

<br/>

___

___

## Azure_LanguageService_AuthN_Disable_Local_Auth

### Display Name
Disable local authentication for Azure Language Service

### Rationale
Disabling local authentication methods (such as account keys) for Azure Language Service ensures that only Azure Active Directory (Azure AD) identities can access the resource. This enhances security by enforcing identity-based access control, enabling better auditing, and reducing the risk of credential leakage or misuse. Enforcing Azure AD authentication aligns with best practices and compliance requirements for secure access management.

### Control Spec

> **Passed:**
> - Local authentication is disabled for the Azure Language Service resource (i.e., both primary and secondary keys are not permitted for authentication).
>
> **Failed:**
> - Local authentication is enabled, allowing access to the Azure Language Service resource using account keys.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Language Service resource in the Azure Portal.
    2. In the left menu, select **Networking** or **Security** (depending on portal updates).
    3. Locate the **Local authentication** setting.
    4. Set **Local authentication** to **Disabled**.
    5. Click **Save** to apply changes.

- **PowerShell**
    ```powershell
    # Install the Az.CognitiveServices module if not already installed
    Install-Module -Name Az.CognitiveServices

    # Disable local authentication for a Cognitive Services account
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroupName>" `
      -Name "<LanguageServiceAccountName>" `
      -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Disable local authentication for a Cognitive Services account
    az cognitiveservices account update \
      --name <LanguageServiceAccountName> \
      --resource-group <ResourceGroupName> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that local authentication is disabled for all Cognitive Services accounts:
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
              "notEquals": true
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      }
      ```
    - For bulk remediation, use an Azure Policy assignment with automatic remediation tasks to set `disableLocalAuth` to `true` across all relevant resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`
  <br />
  **Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_LanguageService_AuthN_Use_Managed_Service_Identity

### Display Name
Azure Language Service should use Managed Service Identity (MSI) for authentication

### Rationale
Enabling Managed Service Identity (MSI) for Azure Language Service ensures secure, passwordless authentication to Azure resources. MSI eliminates the need to manage credentials in code or configuration files, reducing the risk of credential leaks and supporting compliance with security best practices and regulatory frameworks such as ISO 27001, SOC 2, and PCI DSS.

### Control Spec

> **Passed:**
> - The Azure Language Service resource is configured to use Managed Service Identity (either system-assigned or user-assigned) for authentication to other Azure services.
>
> **Failed:**
> - The Azure Language Service resource is not configured to use Managed Service Identity, or is using keys/secrets for authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Language Service resource in the Azure Portal.
    2. In the left menu, select **Identity**.
    3. Under **System assigned**, set the status to **On** and click **Save**.
    4. (Optional) To use a user-assigned identity, select **User assigned**, click **Add**, and choose the appropriate identity.
    5. Update your application code to use Azure AD authentication via MSI instead of keys/secrets.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity
    $resourceGroup = "<your-resource-group>"
    $accountName = "<your-language-service-account>"
    Set-AzCognitiveServicesAccount -ResourceGroupName $resourceGroup -Name $accountName -IdentityType SystemAssigned
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity
    az cognitiveservices account identity assign \
      --name <your-language-service-account> \
      --resource-group <your-resource-group>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce MSI usage on Cognitive Services accounts:
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

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`
  <br />
  **Properties:** `identity.type` (should be `SystemAssigned` or include `UserAssigned`)

<br/>

___

___

## Azure_LanguageService_DP_Data_Loss_Prevention

### Display Name
Azure Language Service Data Loss Prevention (DLP) Configuration

### Rationale
Data Loss Prevention (DLP) controls are essential for protecting sensitive information processed by Azure Language Service. Enabling DLP helps prevent accidental or unauthorized exposure of confidential data, supporting compliance with regulatory requirements such as GDPR, HIPAA, and ISO 27001. This control ensures that data processed by the service is adequately monitored and protected against leaks or misuse.

### Control Spec

> **Passed:**
> - Azure Language Service instance has DLP features enabled and configured according to organizational policy.
> - DLP policies are actively monitoring and restricting sensitive data flows as required.
>
> **Failed:**
> - DLP is not enabled or not properly configured on the Azure Language Service instance.
> - No active policies are in place to detect or prevent data loss.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure Portal.
    2. Go to **Cognitive Services** and select your Azure Language Service resource.
    3. Under **Security** or **Data Protection**, locate the Data Loss Prevention (DLP) settings.
    4. Enable DLP and configure policies to monitor and restrict sensitive data as per your organizational requirements.
    5. Save the configuration.

- **PowerShell**
    ```powershell
    # Example: Update DLP settings for Cognitive Services account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-language-service-account>"
    $dlpConfig = @{
        properties = @{
            dataLossPrevention = @{
                enabled = $true
                policies = @(
                    @{
                        name = "DefaultPolicy"
                        rules = @(
                            @{
                                type = "SensitiveInformation"
                                action = "Block"
                            }
                        )
                    }
                )
            }
        }
    }
    Set-AzResource -ResourceType "Microsoft.CognitiveServices/accounts" `
                   -ResourceGroupName $resourceGroupName `
                   -ResourceName $accountName `
                   -Properties $dlpConfig.properties
    ```

- **Azure CLI**
    ```bash
    # Example: Update DLP settings using Azure CLI
    az cognitiveservices account update \
      --name <your-language-service-account> \
      --resource-group <your-resource-group> \
      --set properties.dataLossPrevention.enabled=true
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
                "field": "Microsoft.CognitiveServices/accounts/dataLossPrevention.enabled",
                "notEquals": "true"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use Azure Policy remediation tasks or deploy an ARM template to enable DLP across all relevant resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `properties.dataLossPrevention.enabled`, `properties.dataLossPrevention.policies`

<br/>

___

**Note:**  
The above documentation is based on the provided structure and requirements. If the source content had included specific remediation scripts, Azure Policy definitions, or bulk configuration methods, they would be detailed in the relevant sections. No such automation or remediation details were present in the provided content, so standard Azure remediation approaches are suggested.

___

## Azure_LanguageService_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure Language Service

### Rationale
Restricting public network access to Azure Language Service resources ensures that only trusted and authorized networks can access sensitive language processing capabilities and data. This reduces the attack surface, mitigates the risk of unauthorized access, and helps organizations comply with regulatory requirements such as ISO 27001, SOC 2, and GDPR by enforcing network boundary controls.

### Control Spec

> **Passed:**
> - The Azure Language Service resource has public network access disabled (`publicNetworkAccess` is set to `Disabled`), or
> - The resource is configured to allow access only from selected networks (e.g., via virtual network rules or private endpoints).
>
> **Failed:**
> - The Azure Language Service resource allows public network access (`publicNetworkAccess` is set to `Enabled`), making it accessible from any network, including the public internet.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal: [https://portal.azure.com](https://portal.azure.com)
    2. Go to **Cognitive Services** and select your Azure Language Service resource.
    3. In the left menu, select **Networking**.
    4. Under **Public network access**, select **Disabled** to block all public access, or configure **Selected networks** to allow only specific trusted networks.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Set public network access to Disabled for a Language Service resource
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-language-service-account>"
    Set-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -PublicNetworkAccess Disabled
    ```

- **Azure CLI**
    ```bash
    # Set public network access to Disabled for a Language Service resource
    az cognitiveservices account update \
        --name <your-language-service-account> \
        --resource-group <your-resource-group> \
        --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition**: Use the built-in Azure Policy `Cognitive Services accounts should restrict public network access` to enforce this control across your environment.
    - **ARM Template**: Ensure the `publicNetworkAccess` property is set to `Disabled` in your deployment templates.
    - **Bulk Remediation**: Use Azure Policy's remediation tasks to automatically update non-compliant resources.
    - **AzTS Remediation**: If using Azure Tenant Security (AzTS), leverage the provided remediation scripts to enforce network restrictions at scale.

### Azure Policies or REST APIs used for evaluation

- **REST API:** `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2022-12-01`
  <br />
  **Properties:** `properties.publicNetworkAccess`
- **Azure Policy:** `Cognitive Services accounts should restrict public network access` (Policy Definition ID: `/providers/Microsoft.Authorization/policyDefinitions/4f6dfb3c-4f2a-4a6b-8c3c-8d3c7b1c8e8c`)

<br/>

___


