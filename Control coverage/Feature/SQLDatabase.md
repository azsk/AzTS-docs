# SQLDatabase

**Resource Type:** Microsoft.Sql/servers/databases

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_SQLDatabase_BCDR_Configure_Geo_Redundancy](#azure_sqldatabase_bcdr_configure_geo_redundancy)
- [Azure_SQL_Database_DP_Enable_Encryption_With_Secure_Enclaves](#azure_sql_database_dp_enable_encryption_with_secure_enclaves)

<!-- /TOC -->
<br/>

___

## Azure_SQLDatabase_BCDR_Configure_Geo_Redundancy

### Display Name
SQL Database must be configured with geo-redundant backup

### Rationale
Geo-redundant backup provides protection against regional disasters by automatically replicating database backups to a paired region, ensuring business continuity and disaster recovery capabilities.

### Control Settings 
```json
{
    "RequiredBackupStorageRedundancy": ["Geo", "GeoZone"],
    "ExcludedDatabaseTypes": ["master", "tempdb", "model", "msdb"]
}
```

### Control Spec

> **Passed:**
> SQL Database is configured with geo-redundant backup storage.
>
> **Failed:**
> SQL Database is not configured with geo-redundant backup storage.
>
> **NotApplicable:**
> Database is a system database or managed instance database.
>

### Recommendation

- **Azure Portal**

    Go to SQL Database ? Configure ? Backup storage redundancy ? Select "Geo-redundant backup storage" or "Geo-zone-redundant backup storage" ? Apply.

### Azure Policies or REST APIs used for evaluation

- REST API to get SQL Database configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}<br />
**Properties:** properties.requestedBackupStorageRedundancy, properties.currentBackupStorageRedundancy<br />

<br />

___

## Azure_SQLDatabase_DP_Enable_Encryption_With_Secure_Enclaves

### Display Name
Enable Always Encrypted with Secure Enclaves on Azure SQL Database

### Rationale
Enabling Always Encrypted with Secure Enclaves ensures that sensitive data stored in Azure SQL Database remains protected, even when in use. Secure Enclaves provide an isolated execution environment within the database engine, allowing computations on encrypted data without exposing the data to the SQL Server instance or database administrators. This control helps organizations meet compliance requirements for data protection, such as GDPR, HIPAA, and other regulatory standards that mandate strong encryption and privacy for sensitive data.

### Control Spec

> **Passed:**
> - The Azure SQL Database has Always Encrypted with Secure Enclaves enabled on at least one column in a user table.
>
> **Failed:**
> - The Azure SQL Database does not have Always Encrypted with Secure Enclaves enabled on any column in any user table.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure SQL Database instance.
    2. In the left menu, select **Transparent data encryption** to confirm encryption status.
    3. To enable Always Encrypted with Secure Enclaves:
        - Go to **Security** > **Always Encrypted**.
        - Select the columns you wish to encrypt.
        - Choose **Encryption Type** as "Deterministic" or "Randomized" and ensure "Enable Secure Enclaves" is selected.
        - Complete the wizard to apply encryption with Secure Enclaves.

- **PowerShell**
    ```powershell
    # Example: Enable Always Encrypted with Secure Enclaves on a column
    # Requires Az.Sql module and SQL Server Management Objects (SMO)
    # Connect to the database and use Set-SqlColumnEncryption cmdlet (requires SQL Server PowerShell module)
    # Note: Actual encryption operations are performed client-side using SQL Server Management Studio or PowerShell with SMO

    # Example: Check if Secure Enclaves are enabled
    Get-AzSqlDatabase -ResourceGroupName "<ResourceGroup>" -ServerName "<ServerName>" -DatabaseName "<DatabaseName>" | Select-Object *

    # Use SQL Server Management Studio or client tools to configure Always Encrypted with Secure Enclaves
    ```

- **Azure CLI**
    ```bash
    # There is no direct Azure CLI command to enable Always Encrypted with Secure Enclaves.
    # Use client-side tools such as SQL Server Management Studio (SSMS) to configure encryption.
    ```

- **Automation/Remediation**
    - Use SQL Server Management Studio (SSMS) version 18.4 or later to configure Always Encrypted with Secure Enclaves.
    - For bulk remediation, use PowerShell scripts or SSMS to encrypt multiple columns across databases.
    - Azure Policy: There is currently no built-in Azure Policy to enforce Always Encrypted with Secure Enclaves. Custom policies may be developed to audit configuration.
    - For tenant-wide configuration, automate deployment using ARM templates that specify encryption settings, or use DevOps pipelines to enforce encryption standards during deployment.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}?api-version=2021-11-01`
  <br />
  **Properties:** 
    - `encryptionProtector`
    - `alwaysEncryptedEnclaveType`
    - Column encryption metadata (checked via T-SQL or client tools)

<br/>

___
