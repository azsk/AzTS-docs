# ActionGroups

**Resource Type:** Microsoft.Insights/actionGroups

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ActionGroups_DP_Avoid_Plaintext_Secrets_Trial](#azure_actiongroups_dp_avoid_plaintext_secrets_trial)

<!-- /TOC -->
<br/>

___

## Azure_ActionGroups_DP_Avoid_Plaintext_Secrets_Trial

### Display Name
[Trial] ActionGroups must not have secrets/credentials present in plain text

### Rationale
Keeping secrets/credentials such as DB connection strings, passwords, keys, etc. in plain text can lead to exposure at various avenues during an application's lifecycle. Storing them in a key vault ensures that they are protected at rest.

### Control Settings 
```json
{
    "SecretPatterns": ["password", "secret", "key", "token", "credential"],
    "ScanDepth": "Full",
    "EvaluatedActionTypes": ["WebhookReceiver", "EmailReceiver", "SMSReceiver", "VoiceReceiver", "AzureFunctionReceiver", "LogicAppReceiver", "AutomationRunbookReceiver", "ITSMReceiver"]
}
```

### Control Spec

> **Passed:**
> Action Group configurations do not contain any plaintext secrets or credentials.
>
> **Failed:**
> Plaintext secrets or credentials are detected in Action Group configuration.
>

### Recommendation

- **Azure Portal**

    Navigate to Azure Portal ? Monitor ? Alerts ? Action Groups ? Review each action group configuration for plaintext credentials ? Store all secrets in Azure Key Vault and reference them using Key Vault URIs ? Replace plaintext webhook URLs with Key Vault references.

- **Security Best Practices**

    - Enable Azure Monitor logs for Action Group activities
    - Set up alerts for unauthorized modifications to Action Group configurations
    - Implement principle of least privilege for Action Group management
    - Regular security audits and compliance checks

### Azure Policies or REST APIs used for evaluation

- REST API to list action groups: /subscriptions/{subscriptionId}/providers/Microsoft.Insights/actionGroups<br />
- REST API to get action group details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/actionGroups/{actionGroupName}<br />
**Properties:** properties.webhookReceivers, properties.emailReceivers, properties.automationRunbookReceivers<br />

<br />

___