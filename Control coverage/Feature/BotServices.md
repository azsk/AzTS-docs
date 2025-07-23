# BotServices

**Resource Type:** Microsoft.BotService/botServices

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_BotServices_Audit_Enable_Diagnostic_Settings](#azure_botservices_audit_enable_diagnostic_settings)
- [Azure_BotServices_AuthN_Disable_Local_Auth](#azure_botservices_authn_disable_local_auth)
- [Azure_BotServices_NetSec_Dont_Allow_Public_Network_Access](#azure_botservices_netsec_dont_allow_public_network_access)

<!-- /TOC -->
<br/>

___

## Azure_BotServices_Audit_Enable_Diagnostic_Settings

### Display Name
Diagnostics logs must be enabled for Bot Services

### Rationale
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings 
```json
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "BotRequest",
        "DependencyRequest"
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

    Go to Bot Service ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{botName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___

## Azure_BotServices_AuthN_Disable_Local_Auth

### Display Name
Bot Services must disable local authentication

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

    Go to Bot Service ? Configuration ? Authentication ? Disable local authentication ? Enable Azure Active Directory authentication only.

### Azure Policies or REST APIs used for evaluation

- REST API to get Bot Service properties: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{botName}<br />
**Properties:** properties.disableLocalAuth<br />

<br />

___

## Azure_BotServices_NetSec_Dont_Allow_Public_Network_Access

### Display Name
Bot Services must not allow public network access

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

    Go to Bot Service ? Networking ? Public network access ? Select "Disabled" ? Configure private endpoints for secure access.

### Azure Policies or REST APIs used for evaluation

- REST API to check network access configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{botName}<br />
**Properties:** properties.publicNetworkAccess<br />

<br />

___