# Recovery Services Vault

**Resource Type:** Microsoft.Recoveryservices/vaults

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_RecoveryServicesVault_DP_Enable_Immutability](#azure_recoveryservicesvault_dp_enable_immutability)

<!-- /TOC -->
<br/>

## Azure_RecoveryServicesVault_DP_Enable_Immutability

### Display Name 
Immutability must be enabled and locked on Recovery Services Vault

### Rationale 
Immutable vault can help you protect your backup data by blocking any operations that could lead to loss of recovery points. Further, you can lock the Immutable vault setting to make it irreversible to prevent any malicious actors from disabling immutability and deleting backups.

### Control Spec 

> **Passed:** 
> If vault immutability is enabled and always on.
> 
> **Failed:** 
> If vault immutability is disabled or enabled but not locked on Recovery Services vault.
>
> **NotApplicable:**
> Not Applicable.
>
>
### Recommendation

- **Azure Portal**

To enable Immutable vault for a Recovery Services vault, follow these steps:
  1. Go to the Recovery Services vault for which you want to enable immutability.
  2. On the vault, go to Properties -> Immutable vault and then select Settings.
  3. On Immutable vault, select the Enable vault immutability checkbox to enable immutability for the vault.

At this point, immutability of the vault is reversible and it can be disabled, if needed.
  4. Once you enable immutability, the option to lock the immutability for the vault appears.

Once you enable this lock, it makes immutability setting for the vault irreversible. While this helps secure the backup data in the vault, we recommend you make a well-informed decision when opting to lock. You can also test and validate how the current settings of the vault, backup policies and so on, meet your requirements and can lock the immutability setting later.

  5. Select Apply to save the changes.
 
To enable and lock immutability using :
1. Azure Portal, please refer [this] (https://learn.microsoft.com/en-us/azure/backup/backup-azure-immutable-vault-how-to-manage?tabs=recovery-services-vault) documentation.
2. Powershell please refer [this] (https://learn.microsoft.com/en-us/powershell/module/az.recoveryservices/update-azrecoveryservicesvault?view=azps-12.2.0.)


### Azure Policies or REST APIs used for evaluation

- REST API to list all the recovery services vaults in a subscription:
subscriptions/{0}/providers/Microsoft.RecoveryServices/vaults?api-version=2024-04-01
<br />

- REST API to fetch properties of recovery services vault resource:
 subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.RecoveryServices/vaults/{2}?api-version=2024-04-01
  <br />

___
