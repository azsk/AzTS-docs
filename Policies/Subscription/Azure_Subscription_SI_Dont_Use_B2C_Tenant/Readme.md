## Azure_Subscription_SI_Dont_Use_B2C_Tenant

### DisplayName 
[Remove Azure Active Directory B2C tenant(s) in a subscription](../../../Control%20coverage/Feature/SubscriptionCore.md#Azure_Subscription_SI_Dont_Use_B2C_Tenant)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Audit' effect to view the details of B2C tenants in use at the policy assignment scope.

#### Policy Definition
[Security - Subscription - DontUseB2CTenant](./Security%20-%20Subscription%20-%20DontUseB2CTenant.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |


### Notes
NA