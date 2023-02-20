## Azure_Subscription_SI_Classic_Resources

### DisplayName 
[Remove classic resources on a subscription](../../../Control%20coverage/Feature/SubscriptionCore.md#Azure_Subscription_SI_Classic_Resources)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Deny' effect to disallow users to create any classic resources in subscription (Greenfield Scenario) and with 'Audit' effect to detect non-compliant resources.

#### Policy Definition
[Security - Subscription - RemoveClassicResources](./Security%20-%20Subscription%20-%20RemoveClassicResources.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |


### Notes
NA