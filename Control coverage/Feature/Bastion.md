# Bastion

**Resource Type:** Microsoft.Network/bastionHosts


<!-- TOC -->

- [Azure_Bastion_AuthZ_Disable_Shareable_Link](#azure_bastion_authz_disable_shareable_link)
<!-- /TOC -->
<br/>

___ 

## Azure_Bastion_AuthZ_Disable_Shareable_Link 

### Display Name 
Azure Bastion Shareable links must not be used

### Rationale 
The Bastion Shareable link lets users with local credentials to bypass primary authentication to Azure, MFA requirements and Network Segmentation by allowing direct connectivity to VMs using the link provided. Compromise of such VMs causes a lateral movement risk for any other assets in the same Vnet.
### Control Settings 
```json 
{
    "AllowedSKUs": [
        "Standard"
    ]
}

```

### Control Spec 

> **Passed:** 
One of the following conditions is met:
>   - Bastion sku is of type "basic".
>- Bastion sku is of type "Standard" and Bastion shareable link is disabled.
> 
> **Failed:** 
> Bastion sku is of type "Standard" and Bastion shareable link is enabled.

> 
### Recommendation 

- **Azure Portal** 
   - "To delete all the shareable links: Go to Azure Portal --> Select your Bastion --> Settings blade --> 'Shareable links' --> select all the VMs with links --> Click 'Delete'.
    - To disable shareable link flag: Select your Bastion --> Settings blade --> Configuration --> Uncheck 'Shareable Link' option --> Click 'Apply'.
      

### Azure Policy or ARM API used for evaluation 

- ARM API used to list Bastion hosts and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/bastionHosts?api-version=2022-07-01<br />
**Properties:** 
sku.name , properties.enableShareableLink
 <br />

___ 

