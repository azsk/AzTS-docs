# OpenAI

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_OpenAI_Audit_Enable_Diagnostic_Settings](#azure_openai_audit_enable_diagnostic_settings)
- [Azure_OpenAI_AuthN_Disable_Local_Auth](#azure_openai_authn_disable_local_auth)
- [Azure_OpenAI_AuthN_Use_Managed_Service_Identity](#azure_openai_authn_use_managed_service_identity)
- [Azure_OpenAI_NetSec_Restrict_Public_Network_Access](#azure_openai_netsec_restrict_public_network_access)
- [Azure_OpenAI_DP_Data_Loss_Prevention](#azure_openai_dp_data_loss_prevention)

<!-- /TOC -->
<br/>

___

## Azure_OpenAI_Audit_Enable_Diagnostic_Settings

### Display Name
Azure OpenAI accounts should have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Azure OpenAI accounts ensures that resource-level logs and metrics are collected and exported to a Log Analytics workspace, Event Hub, or Storage Account. This is crucial for auditing, monitoring, and investigating access or usage patterns, and supports compliance with regulatory requirements and organizational security policies. Diagnostic logs provide visibility into operations and can help detect unauthorized access or anomalous activities.

### Control Spec

> **Passed:**
> - Diagnostic settings are enabled on the Azure OpenAI (Cognitive Services) account.
> - Logs are being sent to at least one of the following: Log Analytics workspace, Event Hub, or Storage Account.
>
> **Failed:**
> - No diagnostic settings are configured for the Azure OpenAI account.
> - Logs are not being exported to any supported destination.

### Recommendation

- **Azure Portal**
    1. Go to the [Azure portal](https://portal.azure.com/).
    2. Navigate to **Cognitive Services** and select your Azure OpenAI resource.
    3. In the left menu, select **Diagnostic settings** under the **Monitoring** section.
    4. Click **+ Add diagnostic setting**.
    5. Enter a name for the setting.
    6. Select the categories of logs and metrics you want to collect.
    7. Choose at least one destination: Log Analytics workspace, Event Hub, or Storage Account.
    8. Click **Save**.

- **PowerShell**
    ```powershell
    # Example: Enable diagnostic settings for Azure OpenAI (Cognitive Services) account
    $resourceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
    $workspaceId = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

    Set-AzDiagnosticSetting -ResourceId $resourceId `
        -WorkspaceId $workspaceId `
        -Name "OpenAIDiagnostics" `
        -Enabled $true `
        -Category "AuditLogs", "AllMetrics"
    ```

- **Azure CLI**
    ```bash
    # Example: Enable diagnostic settings for Azure OpenAI (Cognitive Services) account
    az monitor diagnostic-settings create \
        --resource "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>" \
        --workspace "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>" \
        --name "OpenAIDiagnostics" \
        --logs '[{"category": "AuditLogs", "enabled": true}]' \
        --metrics '[{"category": "AllMetrics", "enabled": true}]'
    ```

- **Automation/Remediation**
    - Use Azure Policy definition: **[Deploy Diagnostic Settings for Cognitive Services to Log Analytics workspace](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDefinitionBlade/definitionId/4b4e2c1b-2b5e-4b0d-8e7c-2b6b2a1e1a2c)**
    - Assign this policy to automatically deploy diagnostic settings to all Cognitive Services accounts, including Azure OpenAI.
    - For bulk remediation, use Azure Policy's "Remediate" feature to apply diagnostic settings across all existing resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/microsoft.insights/diagnosticSettings/{name}?api-version=2017-05-01-preview`  
**Properties:**  
- `logs` (categories such as "AuditLogs")  
- `metrics`  
- `workspaceId`, `eventHubAuthorizationRuleId`, or `storageAccountId` (at least one must be configured)

<br/>

___

___

## Azure_OpenAI_AuthN_Disable_Local_Auth

### Display Name
Disable local authentication for Azure OpenAI resources

### Rationale
Disabling local authentication (such as API keys) for Azure OpenAI resources ensures that only Azure Active Directory (Azure AD) identities can access the resource. This enhances security by enforcing strong authentication, centralized identity management, and auditing capabilities. It helps prevent unauthorized access that could occur if API keys are leaked or compromised, and aligns with best practices for securing sensitive AI workloads.

### Control Spec

> **Passed:**
> - Local authentication (API keys) is disabled for the Azure OpenAI resource.
> - Only Azure Active Directory authentication is enabled.
>
> **Failed:**
> - Local authentication (API keys) is enabled for the Azure OpenAI resource.
> - The resource can be accessed using API keys in addition to, or instead of, Azure AD authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure OpenAI resource in the Azure Portal.
    2. In the left pane, select **Keys and Endpoint**.
    3. Locate the **Local authentication** setting.
    4. Set **Local authentication** to **Disabled**.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Disable local authentication for an Azure OpenAI resource
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-openai-account>"
    Update-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -DisableLocalAuth $true
    ```

- **Azure CLI**
    ```bash
    # Disable local authentication for an Azure OpenAI resource
    az cognitiveservices account update \
      --name <your-openai-account> \
      --resource-group <your-resource-group> \
      --set properties.disableLocalAuth=true
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce local authentication is disabled:
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
    - For bulk remediation, use Azure Policy's "DeployIfNotExists" effect to automatically disable local authentication on non-compliant resources.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_OpenAI_AuthN_Use_Managed_Service_Identity

### Display Name
Require Managed Identity for Azure OpenAI Authentication

### Rationale
Enforcing the use of Managed Service Identity (MSI) for Azure OpenAI authentication enhances security by eliminating the need for hard-coded credentials or secrets in application code. Managed identities provide an automatically managed identity in Azure Active Directory (Azure AD) for applications to use when connecting to resources that support Azure AD authentication. This reduces the risk of credential leakage and supports compliance with security best practices and regulatory frameworks such as ISO 27001, SOC 2, and NIST.

### Control Spec

> **Passed:**
> - Azure OpenAI resources are configured to use Managed Service Identity (MSI) for authentication.
> - No client secrets, API keys, or passwords are used for authentication to the Azure OpenAI resource.
>
> **Failed:**
> - Azure OpenAI resources are accessed using client secrets, API keys, or passwords instead of Managed Service Identity.
> - MSI is not enabled or not used for authentication to the Azure OpenAI resource.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure OpenAI resource in the Azure Portal.
    2. Under the "Identity" blade, enable "System assigned managed identity" or "User assigned managed identity" as required.
    3. Assign the necessary Azure RBAC roles (such as Cognitive Services User) to the managed identity for the Azure OpenAI resource.
    4. Update your application code to use Azure AD authentication via the managed identity instead of API keys or client secrets.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity
    az cognitiveservices account identity assign --name <your-openai-resource-name> --resource-group <your-resource-group>
    
    # Assign Cognitive Services User role to the managed identity
    $identity = az cognitiveservices account show --name <your-openai-resource-name> --resource-group <your-resource-group> --query "identity.principalId" -o tsv
    az role assignment create --assignee $identity --role "Cognitive Services User" --scope /subscriptions/<subscription-id>/resourceGroups/<your-resource-group>/providers/Microsoft.CognitiveServices/accounts/<your-openai-resource-name>
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity
    az cognitiveservices account identity assign --name <your-openai-resource-name> --resource-group <your-resource-group>
    
    # Assign Cognitive Services User role to the managed identity
    IDENTITY_PRINCIPAL_ID=$(az cognitiveservices account show --name <your-openai-resource-name> --resource-group <your-resource-group> --query "identity.principalId" -o tsv)
    az role assignment create --assignee $IDENTITY_PRINCIPAL_ID --role "Cognitive Services User" --scope /subscriptions/<subscription-id>/resourceGroups/<your-resource-group>/providers/Microsoft.CognitiveServices/accounts/<your-openai-resource-name>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce managed identity usage for Cognitive Services resources:
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
    - Use Azure Blueprints or ARM templates to ensure all newly deployed Azure OpenAI resources have managed identity enabled by default.
    - For bulk remediation, use AzTS (Azure Tenant Security) scripts to audit and enable managed identity across all Cognitive Services resources in your tenant.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `identity.type` (should be `SystemAssigned` or `UserAssigned`)

<br/>

___

___

## Azure_OpenAI_DP_Data_Loss_Prevention

### Display Name
Azure OpenAI DLP Service Availability

### Rationale
Ensuring the availability of the Azure OpenAI Data Loss Prevention (DLP) service is critical for maintaining continuous protection against data exfiltration and leakage. Service interruptions can result in unmonitored data flows, increasing the risk of sensitive data exposure and non-compliance with regulatory requirements such as GDPR, HIPAA, and ISO 27001. Monitoring service health and implementing remediation steps for outages supports business continuity and upholds security and compliance commitments.

### Control Spec

> **Passed:**
> - The Azure OpenAI DLP service endpoint is available and responding with HTTP 200 OK.
>
> **Failed:**
> - The Azure OpenAI DLP service endpoint returns HTTP 503 Service Unavailable, indicating a temporary outage or disruption in service.

### Recommendation

- **Azure Portal**
    1. Navigate to **Azure Portal** > **Monitor** > **Service Health**.
    2. Check for any active incidents or advisories related to Azure OpenAI or Cognitive Services in your region.
    3. If an outage is reported, subscribe to updates and review the incident details.
    4. After the incident is resolved, verify service restoration by testing the DLP endpoint.

- **PowerShell**
    ```powershell
    # Check Azure Cognitive Services account status
    Get-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroup>" -Name "<AccountName>"

    # Test endpoint availability
    $endpoint = "<Your_OpenAI_DLP_Endpoint>"
    try {
        $response = Invoke-WebRequest -Uri $endpoint -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Output "Service Available"
        } else {
            Write-Output "Service Unavailable"
        }
    } catch {
        Write-Output "Service Unavailable"
    }
    ```

- **Azure CLI**
    ```bash
    # Check Cognitive Services account status
    az cognitiveservices account show --name <AccountName> --resource-group <ResourceGroup>

    # Test endpoint availability
    curl -I <Your_OpenAI_DLP_Endpoint>
    ```

- **Automation/Remediation**
    - **Automated Monitoring:** Implement Azure Monitor or Application Insights to continuously monitor the health of the DLP endpoint. Configure alerts for HTTP 503 or other error responses.
    - **Azure Policy:** Deploy a policy to ensure all Cognitive Services accounts have diagnostic logging enabled for service health monitoring.
    - **Bulk Remediation:** Use Azure Resource Graph or AzTS scripts to identify all affected resources and notify stakeholders or trigger failover mechanisms if available.
    - **Service Health Alerts:** Set up Azure Service Health alerts to notify administrators of outages or service disruptions affecting Cognitive Services or OpenAI DLP endpoints.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
  <br />
  **Properties:** `properties.endpoint`, `properties.provisioningState`, HTTP response status

- REST API (Service Health): `GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ResourceHealth/availabilityStatuses?api-version=2022-10-01`
  <br />
  **Properties:** `properties.availabilityState`

<br/>

___

___

## Azure_OpenAI_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Azure OpenAI resources

### Rationale
Restricting public network access to Azure OpenAI resources ensures that only trusted and authorized networks can access the resource endpoints. This reduces the attack surface, mitigates the risk of unauthorized access, and helps organizations comply with regulatory requirements such as ISO 27001, SOC 2, and NIST 800-53. Enforcing private access aligns with best practices for securing sensitive AI workloads and data.

### Control Spec

> **Passed:**
> - The Azure OpenAI resource has the "Public network access" property set to "Disabled" or "Selected networks", ensuring it is not accessible from all public networks.
>
> **Failed:**
> - The Azure OpenAI resource allows public network access (property set to "Enabled" or "All networks"), making it accessible from the internet.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure portal.
    2. Go to **Cognitive Services** and select your Azure OpenAI resource.
    3. Under **Networking**, select **Public network access**.
    4. Set the option to **Selected networks** or **Disabled**.
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Set public network access to 'Disabled'
    Set-AzCognitiveServicesAccount -ResourceGroupName "<ResourceGroupName>" `
        -Name "<OpenAIResourceName>" `
        -PublicNetworkAccess "Disabled"
    ```

- **Azure CLI**
    ```bash
    # Set public network access to 'Disabled'
    az cognitiveservices account update \
        --name <OpenAIResourceName> \
        --resource-group <ResourceGroupName> \
        --public-network-access Disabled
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**
        You can assign the built-in Azure Policy `Cognitive Services accounts should restrict public network access` to enforce this setting across your environment.
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
        Use Azure Policy's "Remediate" capability to automatically update non-compliant resources.
    - **ARM Template:**
        Ensure the `publicNetworkAccess` property is set to `"Disabled"` or `"SelectedNetworks"` in your deployment templates.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}?api-version=2023-05-01`
<br />
**Properties:** `properties.publicNetworkAccess`

<br/>

___


