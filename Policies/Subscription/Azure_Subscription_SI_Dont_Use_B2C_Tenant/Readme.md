## Azure_Subscription_SI_Dont_Use_B2C_Tenant

### DisplayName 
[Remove Azure Active Directory B2C tenant(s) in a subscription](../../../Control%20coverage/Feature/SubscriptionCore.md#Azure_Subscription_SI_Dont_Use_B2C_Tenant)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Audit' effect to detect non-compliant resources.

#### Policy Definition
[Security - Subscription - DontUseB2CTenant](./Security%20-%20Subscription%20-%20DontUseB2CTenant.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |


### Notes
The policy evaluation has a gap i.e., it doesn't check whether the resource provider `Azure Active Directory` is registered or not. 