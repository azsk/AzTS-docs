# CognitiveServices

**Resource Type:** Microsoft.CognitiveServices/accounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_CognitiveServices_Audit_Enable_Diagnostics_Log](#azure_cognitiveservices_audit_enable_diagnostics_log)
- [Azure_CognitiveServices_AuthN_Disable_Local_Auth](#azure_cognitiveservices_authn_disable_local_auth)
- [Azure_CognitiveServices_AuthN_Use_Managed_Service_Identity](#azure_cognitiveservices_authn_use_managed_service_identity)
- [Azure_CognitiveServices_DP_Data_Loss_Prevention](#azure_cognitiveservices_dp_data_loss_prevention)
- [Azure_CognitiveServices_DP_Enable_Encryption_With_Customer_Managed_Keys](#azure_cognitiveservices_dp_enable_encryption_with_customer_managed_keys)
- [Azure_CognitiveServices_NetSec_Dont_Allow_Public_Network_Access](#azure_cognitiveservices_netsec_dont_allow_public_network_access)
- [Azure_CognitiveServices_NetSec_Use_Private_Endpoint](#azure_cognitiveservices_netsec_use_private_endpoint)

<!-- /TOC -->
<br/>

___

## Azure_CognitiveServices_Audit_Enable_Diagnostics_Log

### Display Name
Diagnostics logs must be enabled for Cognitive Services

### Rationale
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings 
```json
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "Audit",
        "RequestResponse",
        "Trace"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
```

### Control Spec

> **Passed:**
> Required diagnostic logs are enabled with appropriate retention configuration.
>
> **Failed:**
> Diagnostic logs are not enabled or retention period is insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Cognitive Services resource ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___



___

## Azure_CognitiveServices_AuthN_Disable_Local_Auth

### Display Name
Cognitive Services must disable local authentication

### Rationale
Disabling local authentication ensures that only Azure Active Directory-based authentication is used, providing better security, audit trails, and centralized identity management.

### Control Spec

> **Passed:**
> Local authentication is disabled.
>
> **Failed:**
> Local authentication is enabled.
>

### Recommendation

- **Azure Portal**

    Go to Cognitive Services resource ? Keys and Endpoint ? Authentication ? Disable local authentication ? Enable Azure Active Directory authentication only.

### Azure Policies or REST APIs used for evaluation

- REST API to get Cognitive Services account properties: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}<br />
**Properties:** properties.disableLocalAuth<br />

<br />

___



___

## Azure_CognitiveServices_AuthN_Use_Managed_Service_Identity

### Display Name
Cognitive Services must use Managed Service Identity

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

    Go to Cognitive Services resource ? Identity ? Enable system-assigned or user-assigned managed identity ? Assign appropriate roles for accessing other Azure resources.

### Azure Policies or REST APIs used for evaluation

- REST API to get identity configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}<br />
**Properties:** identity.type, identity.principalId<br />

<br />

___



___

## Azure_CognitiveServices_DP_Data_Loss_Prevention

### Display Name
Cognitive Services must implement data loss prevention measures

### Rationale
Data loss prevention helps protect sensitive information from unauthorized access, leakage, or misuse by implementing appropriate controls and monitoring.

### Control Spec

> **Passed:**
> Data loss prevention measures are implemented and configured.
>
> **Failed:**
> Data loss prevention measures are not properly implemented.
>

### Recommendation

- **Azure Portal**

    Implement data loss prevention through network restrictions, access controls, data encryption, and monitoring policies for your Cognitive Services resources.

### Azure Policies or REST APIs used for evaluation

- REST API to check access policies: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}<br />
**Properties:** properties.networkAcls, properties.encryption<br />

<br />

___



___

## Azure_CognitiveServices_DP_Enable_Encryption_With_Customer_Managed_Keys

### Display Name
Cognitive Services must enable encryption with customer-managed keys

### Rationale
Customer-managed keys provide enhanced security and compliance capabilities by allowing organizations to maintain control over their encryption keys.

### Control Spec

> **Passed:**
> Customer-managed key encryption is enabled.
>
> **Failed:**
> Customer-managed key encryption is not enabled.
>

### Recommendation

- **Azure Portal**

    Go to Cognitive Services resource ? Encryption ? Configure customer-managed keys ? Select Key Vault and key ? Enable encryption with customer-managed keys.

### Azure Policies or REST APIs used for evaluation

- REST API to check encryption configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}<br />
**Properties:** properties.encryption.keySource, properties.encryption.keyVaultProperties<br />

<br />

___



___

## Azure_CognitiveServices_NetSec_Dont_Allow_Public_Network_Access

### Display Name
Cognitive Services must not allow public network access

### Rationale
Restricting public network access reduces the attack surface and ensures that access is only allowed from authorized networks.

### Control Spec

> **Passed:**
> Public network access is disabled.
>
> **Failed:**
> Public network access is enabled.
>

### Recommendation

- **Azure Portal**

    Go to Cognitive Services resource ? Networking ? Public network access ? Select "Disabled" ? Configure private endpoints for secure access.

### Azure Policies or REST APIs used for evaluation

- REST API to check network access configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}<br />
**Properties:** properties.publicNetworkAccess<br />

<br />

___



___

## Azure_CognitiveServices_NetSec_Use_Private_Endpoint

### Display Name
Cognitive Services must use private endpoints

### Rationale
Private endpoints provide secure, private connectivity to Cognitive Services over the Azure backbone network, eliminating exposure to the public internet.

### Control Spec

> **Passed:**
> Private endpoints are configured and in use.
>
> **Failed:**
> Private endpoints are not configured.
>

### Recommendation

- **Azure Portal**

    Go to Cognitive Services resource ? Networking ? Private endpoint connections ? Add private endpoint ? Configure private endpoint with appropriate virtual network and subnet.

### Azure Policies or REST APIs used for evaluation

- REST API to check private endpoint connections: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}<br />
**Properties:** properties.privateEndpointConnections<br />

<br />

___


