# AutomationAccounts

**Resource Type:** Microsoft.Automation/automationAccounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_AutomationAccounts_DP_Encrypt_Variables](#azure_automationaccounts_dp_encrypt_variables)

<!-- /TOC -->
<br/>

## Azure_AutomationAccounts_DP_Encrypt_Variables

### Display Name 
Automation account variables must be encrypted

### Rationale 
Encryption helps prevent sensitive data breaches during transfer and storage.

### Control Spec 

> **Passed:** 
> Microsoft Defender for Cloud (MDC) reports the assessment status for the Automation Account as `Healthy`.
> <br>
> OR
> <br>
> Any one of the following condition is met.
> * All associated variables are encrypted.
> * Count of associated variables is zero.
> 
> **Failed:** 
> Microsoft Defender for Cloud (MDC) reports the assessment status for the Automation Account as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy` or `Exempt`.
> <br>
> OR
> <br>
> More than one variable is not encrypted.
>
> **Verify:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the Automation Account as `Not Applicable` with `cause` other than `OffByPolicy` and `Exempt`.
>
> **NotApplicable:**
> Not Applicable.
>
> **Note:** If no Microsoft Defender for Cloud (MDC) assessment is found for the Automation Account, response from the ARM API is considered for the evaluation.
>
### Recommendation

- **Azure Portal**

  Go to Azure Portal --> your Automation Account --> Shared Resources --> Variables. As variable's encrypted state cannot be modified after creation, you need to delete that variable and create another variable with the same name and value with encryption enabled. 

- **PowerShell**

	```powershell

    Connect-AzAccount

    Set-AzContext -Subscription <SubscriptionId>

    $variable = Get-AzAutomationVariable -AutomationAccountName <AutomationAccountName> -ResourceGroupName <RGName> -Name <VariableName>

    # Storing current value of the variable 
    $value = $variable.Value

    Remove-AzAutomationVariable -AutomationAccountName $variable.AutomationAccountName -ResourceGroupName $variable.ResourceGroupName -Name $variable.Name

    New-AzAutomationVariable -AutomationAccountName $variable.AutomationAccountName -ResourceGroupName $variable.ResourceGroupName -Name $variable.Name -Encrypted $true -Value $value

	```

### Azure Policy or ARM API used for evaluation

- ARM API to list all the automation accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22
  <br />
  **Properties:** [*].name
  <br />

- ARM API to get all the associated variables of automation account:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}/variables?api-version=2019-06-01"
  <br />
  **Properties:** [*].properties.isEncrypted

- ARM API to list all security assessments in a Subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
  **Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData 
  <br />
  **Assessment:** 
  b12bc79e-4f12-44db-acda-571820191ddc - [Automation account variables must be encrypted](https://portal.azure.com/#view/Microsoft_Azure_Security/GenericRecommendationDetailsBlade/assessmentKey/b12bc79e-4f12-44db-acda-571820191ddc)

  <br>

___

