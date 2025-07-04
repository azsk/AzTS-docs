# BackupVault

**Resource Type:** Microsoft.DataProtection/backupVaults

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_BackupVault_Audit_Enable_Monitoring](#azure_backupvault_audit_enable_monitoring)
- [Azure_BackupVault_AuthZ_Enable_MultiUserAuthorization](#azure_backupvault_authz_enable_multiuserauthorization)
- [Azure_BackupVault_DP_Enable_Soft_Delete](#azure_backupvault_dp_enable_soft_delete)
- [Azure_BackupVault_DP_Enable_Immutability](#azure_backupvault_dp_enable_immutability)

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

___

## Azure_BackupVault_DP_Enable_Immutability

### Display Name
Enable immutability for Azure Backup Vault

### Rationale
Immutability ensures that backup data stored in Azure Backup Vaults cannot be deleted or modified for a specified retention period. This protects critical backup data from accidental deletion, ransomware attacks, or malicious insider actions. Enabling immutability helps organizations meet compliance requirements for data protection, such as those outlined in ISO 27001, NIST SP 800-53, and other regulatory frameworks.

### Control Spec

> **Passed:**
> - The Azure Backup Vault has immutability enabled for all backup items, ensuring that backup data cannot be deleted or modified before the retention period expires.
>
> **Failed:**
> - The Azure Backup Vault does not have immutability enabled, or backup items can be deleted or altered before their retention period ends.

### Recommendation

- **Azure Portal**
    1. Navigate to the **Azure Portal**.
    2. Go to **Backup center** > **Backup Vaults**.
    3. Select the relevant **Backup Vault**.
    4. Under **Settings**, select **Immutability**.
    5. Enable **Immutability** for the required backup items or vault.
    6. Save your changes.

- **PowerShell**
    ```powershell
    # Install the Az.DataProtection module if not already installed
    Install-Module -Name Az.DataProtection

    # Enable immutability on a backup vault
    $resourceGroupName = "<ResourceGroupName>"
    $vaultName = "<BackupVaultName>"

    # Example: Set Immutability State
    Update-AzDataProtectionBackupVault -ResourceGroupName $resourceGroupName `
        -VaultName $vaultName `
        -ImmutabilityState "Locked"
    ```

- **Azure CLI**
    ```bash
    # Enable immutability on a backup vault
    az dataprotection backup-vault update \
        --resource-group <ResourceGroupName> \
        --vault-name <BackupVaultName> \
        --immutability-state Locked
    ```

- **Automation/Remediation**
    - **Azure Policy:** Deploy the built-in policy definition:  
      `Azure Backup vaults should have immutability enabled`
    - **ARM Template:**  
      Set the `immutabilityState` property to `Locked` in the backup vault resource definition.
    - **Bulk Remediation:**  
      Use Azure Policy remediation tasks to apply immutability settings to all non-compliant backup vaults at scale.
    - **AzTS Remediation:**  
      If using AzTS (Azure Tenant Security), run the provided remediation script to enable immutability across all detected non-compliant backup vaults.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataProtection/backupVaults/{vaultName}?api-version=2023-01-01`
  <br />
  **Properties:**  
  - `properties.immutabilityState`

<br/>

___
