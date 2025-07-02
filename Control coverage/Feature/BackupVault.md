# BackupVault

**Resource Type:** Microsoft.DataProtection/backupVaults

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_BackupVault_Audit_Enable_Monitoring](#azure_backupvault_audit_enable_monitoring)
- [Azure_BackupVault_AuthZ_Enable_MultiUserAuthorization](#azure_backupvault_authz_enable_multiuserauthorization)
- [Azure_BackupVault_DP_Enable_Soft_Delete](#azure_backupvault_dp_enable_soft_delete)

<!-- /TOC -->
<br/>

___

## Azure_BackupVault_Audit_Enable_Monitoring

### Display Name
Backup Vault must enable monitoring and diagnostics

### Rationale
Monitoring and diagnostics provide visibility into backup operations, failures, and security events, enabling proactive management and incident response.

### Control Spec

> **Passed:**
> Monitoring and diagnostic settings are properly configured.
>
> **Failed:**
> Monitoring and diagnostic settings are not configured or insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Backup Vault ? Monitoring ? Configure monitoring alerts and diagnostic settings ? Enable backup operation monitoring and security event logging.

### Azure Policies or REST APIs used for evaluation

- REST API to get Backup Vault configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataProtection/backupVaults/{vaultName}<br />
**Properties:** properties.monitoringSettings<br />

<br />

___

## Azure_BackupVault_AuthZ_Enable_MultiUserAuthorization

### Display Name
Backup Vault must enable multi-user authorization

### Rationale
Multi-user authorization adds an additional layer of security by requiring approval from multiple users for critical operations, preventing unauthorized changes to backup policies and data.

### Control Spec

> **Passed:**
> Multi-user authorization is enabled and properly configured.
>
> **Failed:**
> Multi-user authorization is not enabled or misconfigured.
>

### Recommendation

- **Azure Portal**

    Go to Backup Vault ? Security Features ? Multi-user authorization ? Enable multi-user authorization ? Configure required approvers for critical operations.

### Azure Policies or REST APIs used for evaluation

- REST API to check authorization configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataProtection/backupVaults/{vaultName}<br />
**Properties:** properties.securitySettings.multiUserAuthorization<br />

<br />

___

## Azure_BackupVault_DP_Enable_Soft_Delete

### Display Name
Backup Vault must enable soft delete

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

    Go to Backup Vault ? Security Features ? Soft Delete ? Enable soft delete ? Configure retention period according to organizational requirements (14-180 days).

### Azure Policies or REST APIs used for evaluation

- REST API to check soft delete configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataProtection/backupVaults/{vaultName}<br />
**Properties:** properties.securitySettings.softDeleteSettings<br />

<br />

___