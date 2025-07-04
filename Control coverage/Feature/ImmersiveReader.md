# Immersive Reader

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ImmersiveReader_AuthN_Use_Managed_Service_Identity](#azure_immersivereader_authn_use_managed_service_identity)
- [Azure_ImmersiveReader_NetSec_Restrict_Public_Network_Access](#azure_immersivereader_netsec_restrict_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_ImmersiveReader_AuthN_Use_Managed_Service_Identity

### Display Name
Azure Immersive Reader should use Managed Service Identity (MSI) for authentication

### Rationale
Enabling Managed Service Identity (MSI) for Azure Immersive Reader ensures that the resource can securely access Azure services without storing credentials in code or configuration files. This reduces the risk of credential leakage and supports compliance with security best practices and regulatory requirements such as ISO 27001, SOC 2, and GDPR. Using MSI also simplifies identity and access management by leveraging Azure Active Directory (Azure AD) for authentication.

### Control Spec

> **Passed:**
> - The Azure Immersive Reader resource is configured to use a system-assigned or user-assigned Managed Service Identity for authentication to other Azure resources.
>
> **Failed:**
> - The Azure Immersive Reader resource is not configured with a Managed Service Identity, or authentication is performed using keys, passwords, or other credentials stored in code or configuration.

### Recommendation

- **Azure Portal**
    1. Navigate to your Immersive Reader resource in the Azure Portal.
    2. In the left menu, select **Identity** under the **Settings** section.
    3. Under the **System assigned** tab, set the status to **On** and click **Save**.
    4. (Optional) To use a user-assigned managed identity, select the **User assigned** tab and click **Add** to assign an existing managed identity.
    5. Update your application code to use Azure AD authentication via MSI instead of keys or passwords.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity
    $resourceGroupName = "<your-resource-group>"
    $accountName = "<your-immersive-reader-account>"
    Set-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName `
        -Name $accountName `
        -IdentityType SystemAssigned
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity
    az cognitiveservices account update \
      --name <your-immersive-reader-account> \
      --resource-group <your-resource-group> \
      --set identity.type=SystemAssigned
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce MSI on Cognitive Services accounts:
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
                  "equals": "SystemAssigned"
                }
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
  **Properties:** `identity.type` (should be `SystemAssigned` or `UserAssigned`)

<br/>

___

___

## Azure_ImmersiveReader_NetSec_Restrict_Public_Network_Access

### Display Name
Restrict public network access for Immersive Reader

### Rationale
Restricting public network access to Immersive Reader resources helps prevent unauthorized access from the public internet. By enforcing private endpoint connections or limiting allowed networks, you reduce the attack surface and protect sensitive data processed by Immersive Reader. This control supports compliance with standards such as ISO 27001, SOC 2, and Azure CIS by enforcing network boundary protections.

### Control Spec

> **Passed:**
> - Immersive Reader resource is configured to deny public network access (i.e., "Public network access" is set to "Disabled").
> - Only private endpoints or explicitly allowed networks can access the resource.
>
> **Failed:**
> - Immersive Reader resource allows public network access (i.e., "Public network access" is set to "Enabled" or "All networks").
> - The resource is accessible from the public internet without network restrictions.

### Recommendation

- **Azure Portal**
    1. Navigate to the Immersive Reader resource in the Azure Portal.
    2. In the left pane, select **Networking**.
    3. Under **Public network access**, select **Disabled**.
    4. (Optional) Configure private endpoints or specify allowed networks as needed.
    5. Click **Save** to apply changes.

- **PowerShell**
    ```powershell
    # Replace with your resource group and resource name
    $resourceGroupName = "<your-resource-group>"
    $resourceName = "<your-immersive-reader-resource>"

    # Set public network access to Disabled
    Set-AzResource -ResourceType "Microsoft.Insights/immersiveReaders" `
      -ResourceGroupName $resourceGroupName `
      -ResourceName $resourceName `
      -PropertyObject @{publicNetworkAccess="Disabled"} `
      -ApiVersion "2021-06-01" 
    ```

- **Azure CLI**
    ```bash
    # Replace with your resource group and resource name
    az resource update \
      --resource-type "Microsoft.Insights/immersiveReaders" \
      --name <your-immersive-reader-resource> \
      --resource-group <your-resource-group> \
      --set properties.publicNetworkAccess=Disabled \
      --api-version 2021-06-01
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce this setting across your tenant:
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Insights/immersiveReaders"
            },
            {
              "field": "Microsoft.Insights/immersiveReaders/publicNetworkAccess",
              "notEquals": "Disabled"
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      }
      ```
    - For bulk remediation, use Azure Policy's "DeployIfNotExists" effect to automatically set `publicNetworkAccess` to `Disabled`.
    - Consider using Azure Blueprints or ARM templates for consistent deployment.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/immersiveReaders/{resourceName}?api-version=2021-06-01`  
**Properties:** `publicNetworkAccess`

<br/>

___


