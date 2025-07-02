# RecoveryServicesVault

**Resource Type:** Microsoft.RecoveryServices/vaults

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_RecoveryServicesVault_DP_Enable_Soft_Delete](#azure_recoveryservicesvault_dp_enable_soft_delete)

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