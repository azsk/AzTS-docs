# Content Safety

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ContentSafety_AuthN_Use_Managed_Service_Identity](#azure_contentsafety_authn_use_managed_service_identity)
- [Azure_ContentSafety_AuthN_Disable_Local_Auth](#azure_contentsafety_authn_disable_local_auth)
- [Azure_ContentSafety_DP_Data_Loss_Prevention](#azure_contentsafety_dp_data_loss_prevention)
- [Azure_ContentSafety_NetSec_Restrict_Public_Network_Access](#azure_contentsafety_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_ContentSafety_AuthN_Disable_Local_Auth

### Display Name
Disable local authentication for Azure Content Safety accounts

### Rationale
Disabling local authentication methods (such as account keys or basic authentication) for Azure Content Safety accounts ensures that only Azure Active Directory (Azure AD) identities can access the service. This reduces the risk of credential leakage, brute-force attacks, and unauthorized access, thereby strengthening the security posture and supporting compliance with standards that require strong, centralized identity management.

### Control Spec

> **Passed:**
> Local authentication (e.g., account keys, basic authentication) is disabled for the Azure Content Safety account. Only Azure AD authentication is allowed.
>
> **Failed:**
> Local authentication is enabled, allowing access via account keys or basic authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Content Safety account in the Azure Portal.
    2. Under **Settings**, select **Authentication**.
    3. Ensure that the option for **Allow local authentication** is **disabled**.
    4. Save your changes.

- **PowerShell**
    ```powershell
    # Replace with your resource group and account name
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-content-safety-account>"

    # Disable local authentication
    Set-AzResource -ResourceType "Microsoft.ContentSafety/accounts" `
        -ResourceGroupName $resourceGroupName `
        -ResourceName $accountName `
        -PropertyObject @{ properties = @{ disableLocalAuth = $true } } `
        -ApiVersion "2023-06-01-preview"
    ```

- **Azure CLI**
    ```bash
    # Replace with your resource group and account name
    az resource update \
      --resource-type "Microsoft.ContentSafety/accounts" \
      --resource-group <your-resource-group> \
      --name <your-content-safety-account> \
      --set properties.disableLocalAuth=true \
      --api-version 2023-06-01-preview
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that local authentication is disabled for all Content Safety accounts:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.ContentSafety/accounts"
              },
              {
                "field": "Microsoft.ContentSafety/accounts/disableLocalAuth",
                "notEquals": "true"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use a script to iterate over all Content Safety accounts in your tenant and disable local authentication.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContentSafety/accounts/{accountName}?api-version=2023-06-01-preview`  
**Properties:** `properties.disableLocalAuth`

<br/>

___

___

## Azure_ContentSafety_AuthN_Use_Managed_Service_Identity

### Display Name
Azure Content Safety should use Managed Service Identity (MSI) for authentication

### Rationale
Enabling Managed Service Identity (MSI) for Azure Content Safety resources ensures secure, passwordless authentication to Azure services. MSI eliminates the need to store credentials in code or configuration files, reducing the risk of credential leakage and improving compliance with security best practices and regulatory standards such as ISO 27001 and SOC 2.

### Control Spec

> **Passed:**
> The Azure Content Safety resource is configured to use a system-assigned or user-assigned Managed Service Identity (MSI) for authentication to other Azure services.
>
> **Failed:**
> The Azure Content Safety resource is not configured to use any Managed Service Identity (MSI) for authentication.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Content Safety account in the Azure Portal.
    2. In the left menu, select **Identity** under the **Settings** section.
    3. Under the **System assigned** tab, set the status to **On** and click **Save**.
    4. (Optional) To use a user-assigned identity, select the **User assigned** tab and click **Add**, then select or create a managed identity.
    5. Assign the required roles to the managed identity for the target resources.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity
    az contentsafety account identity assign --name <ContentSafetyAccountName> --resource-group <ResourceGroupName>
    
    # Assign a user-assigned managed identity
    az contentsafety account identity assign --name <ContentSafetyAccountName> --resource-group <ResourceGroupName> --identities <UserAssignedIdentityResourceId>
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity
    az contentsafety account identity assign --name <ContentSafetyAccountName> --resource-group <ResourceGroupName>
    
    # Assign a user-assigned managed identity
    az contentsafety account identity assign --name <ContentSafetyAccountName> --resource-group <ResourceGroupName> --identities <UserAssignedIdentityResourceId>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce that all Azure Content Safety resources have MSI enabled:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.ContentSafety/accounts"
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
    - For bulk remediation, use Azure CLI or PowerShell scripts to enable MSI on all Content Safety accounts in a subscription.

### Azure Policies or REST APIs used for evaluation

- REST API: `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContentSafety/accounts/{accountName}?api-version=2023-10-01`
<br />
**Properties:** `identity.type` (should be `SystemAssigned`, `UserAssigned`, or `SystemAssigned, UserAssigned`)

<br/>

___

___

## Azure_ContentSafety_DP_Data_Loss_Prevention

### Display Name
Ensure Azure Content Safety DLP Service Availability

### Rationale
Maintaining the availability of the Azure Content Safety Data Loss Prevention (DLP) service is critical for ensuring continuous monitoring and protection against data leakage. Service disruptions can result in undetected data exfiltration, regulatory non-compliance, and potential data breaches. Ensuring high availability aligns with compliance standards such as ISO 27001, SOC 2, and GDPR.

### Control Spec

> **Passed:**
> - The Azure Content Safety DLP service endpoint is reachable and returns HTTP 200 (OK) or other successful response codes.
> - No recent incidents of service unavailability (e.g., HTTP 503 errors) are detected.
>
> **Failed:**
> - The Azure Content Safety DLP service returns HTTP 503 (Service Unavailable) or similar error codes.
> - Users are unable to access DLP features due to service outages.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure Content Safety DLP resource in the Azure Portal.
    2. Check the "Service Health" blade for any ongoing incidents or advisories.
    3. If a service outage is reported, subscribe to Azure Service Health alerts for timely notifications.
    4. Review the "Activity Log" for any recent changes or disruptions.
    5. If the issue persists, open a support ticket with Microsoft Azure Support.

- **PowerShell**
    ```powershell
    # Check Azure Content Safety DLP resource status
    Get-AzResource -ResourceType "Microsoft.ContentSafety/dataLossPrevention" | Get-AzResourceHealth
    ```

- **Azure CLI**
    ```bash
    # Check Azure Content Safety DLP resource status
    az resource show --resource-type Microsoft.ContentSafety/dataLossPrevention --name <resource-name> --query "properties.status"
    ```

- **Automation/Remediation**
    - Implement Azure Monitor alerts to detect HTTP 503 or service unavailability events for the DLP service.
    - Use Azure Service Health to automate notifications and escalation workflows.
    - Deploy an Azure Policy to ensure that critical security services, including Content Safety DLP, are monitored for availability.
    - Example Azure Policy definition (pseudo-code):
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.ContentSafety/dataLossPrevention"
              },
              {
                "field": "properties.status",
                "notEquals": "Available"
              }
            ]
          },
          "then": {
            "effect": "audit"
          }
        }
        ```

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContentSafety/dataLossPrevention/{resourceName}?api-version=2023-01-01`<br />
**Properties:** `properties.status`, HTTP response code

<br/>

___

___

## Azure_ContentSafety_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict Public Network Access for Azure Content Safety

### Rationale
Restricting public network access to Azure Content Safety resources ensures that only authorized private endpoints or trusted networks can communicate with the service. This reduces the attack surface, prevents unauthorized access from the public internet, and helps organizations comply with regulatory requirements such as ISO 27001, SOC 2, and NIST 800-53.

### Control Spec

> **Passed:**
> - The Azure Content Safety resource is configured to deny public network access (i.e., `publicNetworkAccess` is set to `Disabled`).
> - Only private endpoints or trusted subnets are allowed to access the resource.
>
> **Failed:**
> - The Azure Content Safety resource allows public network access (i.e., `publicNetworkAccess` is set to `Enabled` or not explicitly set).
> - The resource is accessible from the public internet.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Content Safety resource in the Azure Portal.
    2. Select **Networking** from the left-hand menu.
    3. Under **Public network access**, select **Disabled**.
    4. Save your changes.

- **PowerShell**
    ```powershell
    # Set public network access to Disabled for a Content Safety account
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-content-safety-account>"
    Update-AzResource -ResourceType "Microsoft.ContentSafety/accounts" `
        -ResourceGroupName $resourceGroupName `
        -ResourceName $accountName `
        -ApiVersion "2023-10-01" `
        -PropertyObject @{ properties = @{ publicNetworkAccess = "Disabled" } }
    ```

- **Azure CLI**
    ```bash
    # Set public network access to Disabled for a Content Safety account
    az resource update \
      --resource-type "Microsoft.ContentSafety/accounts" \
      --name "<your-content-safety-account>" \
      --resource-group "<your-resource-group>" \
      --set properties.publicNetworkAccess=Disabled \
      --api-version 2023-10-01
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can assign a built-in or custom Azure Policy to enforce that all Azure Content Safety resources have public network access disabled.
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.ContentSafety/accounts"
            },
            {
              "field": "Microsoft.ContentSafety/accounts/publicNetworkAccess",
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
      Use Azure Policy's "DeployIfNotExists" effect to automatically remediate non-compliant resources at scale.
    - **Governance Tools:**  
      Integrate with Azure Blueprints or Azure Security Center to monitor and enforce this control across your tenant.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContentSafety/accounts/{accountName}?api-version=2023-10-01`  
**Properties:** `properties.publicNetworkAccess`

<br/>

___


