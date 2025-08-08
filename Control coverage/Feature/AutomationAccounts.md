# AutomationAccounts

**Resource Type:** Microsoft.Automation/automationAccounts

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_AutomationAccounts_DP_Encrypt_Variables](#azure_automationaccounts_dp_encrypt_variables)
- [Azure_AutomationAccounts_DP_Avoid_Plaintext_Secrets](#azure_automationaccounts_dp_avoid_plaintext_secrets)

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

### Azure Policies or REST APIs used for evaluation

- REST API to list all the automation accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22
  <br />
  **Properties:** [*].name
  <br />

- REST API to get all the associated variables of automation account:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}/variables?api-version=2019-06-01"
  <br />
  **Properties:** [*].properties.isEncrypted

- REST API to list all security assessments in a Subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
  **Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData 
  <br />
  **Assessment:** 
  b12bc79e-4f12-44db-acda-571820191ddc - [Automation account variables must be encrypted](https://portal.azure.com/#view/Microsoft_Azure_Security/GenericRecommendationDetailsBlade/assessmentKey/b12bc79e-4f12-44db-acda-571820191ddc)

  <br>

___



___

## Azure_AutomationAccounts_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing plaintext secrets in Azure Automation Accounts

### Rationale
Storing secrets such as passwords, connection strings, or API keys in plaintext within Azure Automation Accounts poses a significant security risk. Plaintext secrets can be inadvertently exposed through logs, scripts, or configuration files, leading to unauthorized access and potential data breaches. Using secure alternatives like Azure Key Vault ensures secrets are encrypted at rest and access is tightly controlled, supporting compliance with security frameworks such as ISO 27001, SOC 2, and NIST.

### Control Spec

> **Passed:**
> No plaintext secrets (e.g., passwords, connection strings, API keys) are stored in Automation Account variables, runbooks, or configuration files. All sensitive data is referenced securely, such as through Azure Key Vault integration.
>
> **Failed:**
> Any plaintext secret is detected in Automation Account variables, runbooks, or configuration files, or secrets are not referenced securely.

### Recommendation

- **Azure Portal**
    1. Navigate to your Automation Account in the Azure Portal.
    2. Review all variables and runbooks for hardcoded secrets.
    3. Remove any plaintext secrets and replace them with secure references (e.g., retrieve secrets at runtime from Azure Key Vault).
    4. Integrate your Automation Account with Azure Key Vault:
        - Go to "Identity" under your Automation Account and enable a managed identity.
        - Assign the managed identity appropriate permissions (e.g., "Get" on secrets) in your Key Vault.
        - Update runbooks to use the managed identity to retrieve secrets from Key Vault.

- **PowerShell**
    ```powershell
    # Example: Remove a plaintext variable
    Remove-AzAutomationVariable -ResourceGroupName "<resource-group>" `
        -AutomationAccountName "<automation-account>" `
        -Name "<variable-name>"

    # Example: Retrieve a secret from Key Vault in a runbook
    $Secret = Get-AzKeyVaultSecret -VaultName "<keyvault-name>" -Name "<secret-name>"
    ```

- **Azure CLI**
    ```bash
    # Remove a plaintext variable
    az automation variable delete \
      --resource-group <resource-group> \
      --automation-account-name <automation-account> \
      --name <variable-name>

    # Assign Key Vault access policy to Automation Account's managed identity
    az keyvault set-policy \
      --name <keyvault-name> \
      --object-id <automation-account-managed-identity-object-id> \
      --secret-permissions get list
    ```

- **Automation/Remediation**
    - **Azure Policy:** Deploy a policy to audit or deny Automation Account variables containing sensitive keywords (e.g., "password", "secret", "key").
    - **Scripted Remediation:** Use scripts to scan Automation Account variables and runbooks for potential plaintext secrets and alert or remove them.
    - **Bulk Configuration:** Use Azure Policy or custom scripts to enforce Key Vault integration across all Automation Accounts in your tenant.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}/variables?api-version=2022-08-08`
  <br />
  **Properties:** `value.properties.value` (for plaintext secret detection)

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}/runbooks?api-version=2022-08-08`
  <br />
  **Properties:** `properties.description`, `properties.logVerbose`, `properties.logProgress`, and runbook content (for secret scanning)

<br/>

___
