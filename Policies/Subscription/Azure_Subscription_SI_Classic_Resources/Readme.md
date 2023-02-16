## Azure_Subscription_SI_Classic_Resources

### DisplayName 
[Remove classic resources on a subscription](../../../Control%20coverage/Feature/SubscriptionCore.md)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Deny' effect to disallow users to create any classic resources in subscription (Greenfield Scenario).

#### Policy Definition
[Security - Subscription - ClassicResources](Security%20-%20Subscription%20-%20ClassicResources.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy| Deny |No |


### Notes
NA