# Backup Vault

**Resource Type:** Microsoft.DataProtection/backupVaults

<!-- TOC depthfrom:2 depthto:2 -->

- [	Azure_BackupVault_DP_Enable_Immutability](#azure_backupvault_dp_enable_immutability)

<!-- /TOC -->
<br/>

## Azure_BackupVault_DP_Enable_Immutability

### Display Name 
Immutability must be enabled and locked on Backup Vault

### Rationale 
Immutable vault can help you protect your backup data by blocking any operations that could lead to loss of recovery points. Further, you can lock the Immutable vault setting to make it irreversible to prevent any malicious actors from disabling immutability and deleting backups.

### Control Spec 

> **Passed:** 
> If vault immutability is enabled and always on.
> 
> **Failed:** 
> If vault immutability is disabled or enabled but not locked on backup vault.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- **Azure Portal**

To enable Immutable vault for a Backup vault, follow these steps:
  1. Go to the Backup vault for which you want to enable immutability.
  2. On the vault, go to Properties -> Immutable vault and then select Settings.
  3. On Immutable vault, select the Enable vault immutability checkbox to enable immutability for the vault.

At this point, immutability of the vault is reversible and it can be disabled, if needed.

  4. Select Apply to save the changes.
 
To enable and lock immutability using Azure Portal, please refer [this] (https://learn.microsoft.com/en-us/azure/backup/backup-azure-immutable-vault-how-to-manage?tabs=backup-vault#enable-immutable-vault) documentation.

- **Powershell**

```powershell

Update-AzDataProtectionBackupVault -VaultName '{VaultName}' -ResourceGroupName '{ResourceGroupName}' -ImmutabilityState Locked

```

Please refer: https://learn.microsoft.com/en-us/powershell/module/az.dataprotection/update-azdataprotectionbackupvault?view=azps-10.0.0#syntax


### Azure Policies or REST APIs used for evaluation

- REST API to list all the backup vaults in a subscription:
subscriptions/{0}/providers/Microsoft.DataProtection/backupVaults?api-version=2023-01-01
<br />

___
