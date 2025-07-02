# ServiceBus

**Resource Type:** Microsoft.ServiceBus/namespaces

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ServiceBus_AuthN_Disable_Local_Auth](#azure_servicebus_authn_disable_local_auth)

<!-- /TOC -->
<br/>

___

## Azure_ServiceBus_AuthN_Disable_Local_Auth

### Display Name
Service Bus must disable local authentication

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

    Go to Service Bus namespace ? Configuration ? Local authentication ? Disabled ? Save.

### Azure Policies or REST APIs used for evaluation

- REST API to get Service Bus namespace properties: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}<br />
**Properties:** properties.disableLocalAuth<br />

<br />

___


