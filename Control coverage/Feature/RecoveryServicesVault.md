# RecoveryServicesVault

**Resource Type:** Microsoft.RecoveryServices/vaults

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_RecoveryServicesVault_DP_Enable_Soft_Delete](#azure_recoveryservicesvault_dp_enable_soft_delete)
- [Azure_RecoveryServicesVault_D_P_Enable_Immutability](#azure_recoveryservicesvault_d_p_enable_immutability)

<!-- /TOC -->
<br/>

___

## Azure_RecoveryServicesVault_DP_Enable_Soft_Delete

### Display Name
Recovery Services Vault must enable soft delete

### Rationale
Soft delete protects backup data from accidental or malicious deletion by retaining deleted backups for a recovery period, allowing restoration if needed.

### Control Settings 
```json
{
  "RequireSoftDelete": true,
  "MinimumRetentionDays": 14,
  "MaximumRetentionDays": 180
}
```

### Control Spec

> **Passed:**
> Soft delete is enabled with appropriate retention settings.
>
> **Failed:**
> Soft delete is disabled or retention settings are insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Recovery Services Vault ? Properties ? Security Settings ? Soft Delete ? Enable soft delete ? Configure retention period according to organizational requirements (14-180 days).

- **PowerShell**

    ```powershell
    Set-AzRecoveryServicesVaultProperty -Vault $vault -SoftDeleteFeatureState "Enable"
    ```

### Azure Policies or REST APIs used for evaluation

- REST API to check soft delete configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}<br />
**Properties:** properties.securitySettings.softDeleteSettings<br />

<br />

___


## Azure_RecoveryServicesVault_DP_Enable_Immutability

### Display Name
Recovery Services Vaults should have immutability enabled

### Rationale
Enabling immutability on Azure Recovery Services Vaults ensures that backup data cannot be modified or deleted before the retention period expires. This is critical for protecting backup data against accidental deletion, ransomware attacks, or malicious insider actions. Immutability helps organizations meet regulatory compliance requirements (such as GDPR, HIPAA, and financial sector mandates) by ensuring data integrity and retention.

### Control Spec

> **Passed:**
> - The Recovery Services Vault has immutability enabled for backup items, ensuring that backup data cannot be deleted or modified before the configured retention period.
>
> **Failed:**
> - The Recovery Services Vault does not have immutability enabled, allowing backup data to be deleted or altered before the retention period expires.

### Recommendation

- **Azure Portal**
    1. Navigate to **Recovery Services vaults** in the Azure Portal.
    2. Select the target vault.
    3. Under **Settings**, select **Backup policies**.
    4. Edit the backup policy or create a new one.
    5. In the **Immutability** section, set **Immutability** to **Enabled**.
    6. Save the policy and assign it to the relevant backup items.

- **PowerShell**
    ```powershell
    # Example: Enable immutability on a backup policy
    $vaultName = "<YourVaultName>"
    $resourceGroupName = "<YourResourceGroup>"
    $policyName = "<YourBackupPolicyName>"

    # Get the backup policy
    $policy = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId "/subscriptions/<subscriptionId>/resourceGroups/$resourceGroupName/providers/Microsoft.RecoveryServices/vaults/$vaultName" -Name $policyName

    # Enable immutability
    $policy.IsImmutabilityEnabled = $true

    # Update the policy
    Set-AzRecoveryServicesBackupProtectionPolicy -Policy $policy
    ```

- **Azure CLI**
    ```bash
    # There is currently no direct Azure CLI command to enable immutability on a backup policy.
    # Use PowerShell or the Azure Portal for this configuration.
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce immutability on Recovery Services Vault backup policies:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.RecoveryServices/vaults/backupPolicies"
              },
              {
                "field": "Microsoft.RecoveryServices/vaults/backupPolicies/immutabilitySettings.state",
                "notEquals": "Enabled"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - Bulk remediation can be performed using PowerShell scripts to enumerate all vaults and policies, enabling immutability where missing.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupPolicies/{policyName}?api-version=2023-01-01`
  <br />
  **Properties:** `properties.immutabilitySettings.state`

<br/>

___
