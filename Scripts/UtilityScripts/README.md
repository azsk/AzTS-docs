# Azure Tenant Scanner Powershell Utility Scripts

This readme describes the Powershell functions available in [AzTSUtility.ps1](AzTSUtility.ps1).

The functions are provided to help with assessment and remediation of Azure Tenant Scanner control compliance issues. The controls and provided functions are listed below.

## Contents

- [Azure Tenant Scanner Powershell Utility Scripts](#azure-tenant-scanner-powershell-utility-scripts)
  - [Contents](#contents)
  - [Pre-Requisites](#pre-requisites)
  - [How to use](#how-to-use)
    - [Powershell Execution Policy](#powershell-execution-policy)
  - [Controls and Functions](#controls-and-functions)
    - [Azure\_AppService\_DP\_Use\_Secure\_FTP\_Deployment](#azure_appservice_dp_use_secure_ftp_deployment)
    - [Azure\_DataFactory\_DP\_Avoid\_Plaintext\_Secrets](#azure_datafactory_dp_avoid_plaintext_secrets)
    - [Azure\_DBForMYSQLFlexibleServer\_DP\_Enable\_SSL](#azure_dbformysqlflexibleserver_dp_enable_ssl)
    - [Azure\_DBForMySQLFlexibleServer\_TLS](#azure_dbformysqlflexibleserver_tls)
    - [Azure\_SQLManagedInstance\_DP\_Use\_Secure\_TLS\_Version](#azure_sqlmanagedinstance_dp_use_secure_tls_version)
    - [Azure\_KeyVault\_NetSec\_Disable\_Public\_Network\_Access](#azure_keyvault_netsec_disable_public_network_access)
    - [Azure\_Subscription\_AuthZ\_Remove\_Deprecated\_Accounts](#azure_subscription_authz_remove_deprecated_accounts)
    - [Azure\_Subscription\_DP\_Avoid\_Plaintext\_Secrets\_Deployments](#azure_subscription_dp_avoid_plaintext_secrets_deployments)
    - [Azure\_Subscription\_SI\_Dont\_Use\_B2C\_Tenant](#azure_subscription_si_dont_use_b2c_tenant)
    - [Azure\_VirtualMachine\_SI\_Enable\_Antimalware](#azure_virtualmachine_si_enable_antimalware)

## Pre-Requisites

- Windows Powershell 5.1 or [Powershell 7.x+](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
- [Azure Powershell](https://learn.microsoft.com/powershell/azure/install-az-ps)

Note that you can also use the [Azure Cloud Shell](https://shell.azure.com) (select Powershell, not Bash), which has all required pre-requisites already installed.

## How to use

- Ensure you meet the pre-requisites above
- Log into Azure with Connect-AzAccount
- Download [AzTSUtility.ps1](AzTSUtility.ps1)
- Open a Powershell prompt where you downloaded AzTSUtility.ps1
- Dot-source as follows: `. ./AzTSUtility.ps1`
- Now you can run the various functions with their required parameters - see below

### Powershell Execution Policy

To run this or other downloaded scripts, you may need to set your Powershell execution policy.
Reference: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies

Example so you can run script and functions in a downloaded file like AzTSUtility.ps1:
`Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser`

Example to then reset the execution policy either to default (Restricted) or RemoteSigned:
`Set-ExecutionPolicy -ExecutionPolicy Default -Scope CurrentUser`
`Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

## Controls and Functions

### Azure_AppService_DP_Use_Secure_FTP_Deployment

`Get-AppServiceFtpState()`
Purpose: Lists the App Service's production slot and all non-production slots, each with its current FTP state.
Parameters: SubscriptionId, ResourceGroupName, AppServiceName

`Set-AppServiceFtpState()`
Purpose: Sets the specified App Service slot's FTP state.
Parameters: SubscriptionId, ResourceGroupName, AppServiceName, SlotName, FtpState

### Azure_DataFactory_DP_Avoid_Plaintext_Secrets

`Get-DataFactoryV2()`
Purpose: Show the Data Factory so that it can be inspected for plain-text secrets.
Parameters: SubscriptionId, ResourceGroupName, DataFactoryName

`Get-DataFactoryV2DataFlows()`
Purpose: Show the Data Factory Data Flows so they can be inspected for plain-text secrets.
Parameters: SubscriptionId, ResourceGroupName, DataFactoryName

`Get-DataFactoryV2DataSets()`
Purpose: Show the Data Factory Data Sets so they can be inspected for plain-text secrets.
Parameters: SubscriptionId, ResourceGroupName, DataFactoryName

`Get-DataFactoryV2IntegrationRuntimes()`
Purpose: Show the Data Factory Integration Runtimes so they can be inspected for plain-text secrets.
Parameters: SubscriptionId, ResourceGroupName, DataFactoryName

`Get-DataFactoryV2LinkedServices()`
Purpose: Show the Data Factory Linked Services so they can be inspected for plain-text secrets.
Parameters: SubscriptionId, ResourceGroupName, DataFactoryName

`Get-DataFactoryV2Pipelines()`
Purpose: Show the Data Factory Pipelines so they can be inspected for plain-text secrets.
Parameters: SubscriptionId, ResourceGroupName, DataFactoryName

`Get-DataFactoryV2Triggers()`
Purpose: Show the Data Factory Triggers so they can be inspected for plain-text secrets.
Parameters: SubscriptionId, ResourceGroupName, DataFactoryName

### Azure_DBForMYSQLFlexibleServer_DP_Enable_SSL

`Get-MySqlFlexServerSslState()`
Purpose: Show the MySQL Flexible Server's current SSL state configured via the `require_secure_transport` server parameter.
Parameters: SubscriptionId, ResourceGroupName, ServerName

`Set-MySqlFlexServerSslState()`
Purpose: Sets the MySQL Flexible Server's SSL state configured via the `require_secure_transport` server parameter.
Parameters: SubscriptionId, ResourceGroupName, ServerName, SslSetting

### Azure_DBForMySQLFlexibleServer_TLS

`Get-MySqlFlexServerTlsVersion()`
Purpose: Show the MySQL Flexible Server's current minimum TLS version configured via the `tls_version` server parameter.
Parameters: SubscriptionId, ResourceGroupName, ServerName

`Set-MySqlFlexServerTlsVersion()`
Purpose: Sets the MySQL Flexible Server's minimum TLS version configured via the `tls_version` server parameter.
Parameters: SubscriptionId, ResourceGroupName, ServerName, TlsVersion

### Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version

`Get-SqlManagedInstanceMinimumTlsVersion()`
Purpose: Show the Azure SQL DB Managed Instance's current minimum TLS version.
Parameters: SubscriptionId, ResourceGroupName, SqlInstanceName

`Set-SqlManagedInstanceMinimumTlsVersion()`
Purpose: Sets the Azure SQL DB Managed Instance's minimum TLS version.
Parameters: SubscriptionId, ResourceGroupName, SqlInstanceName, MinimalTlsVersion

### Azure_KeyVault_NetSec_Disable_Public_Network_Access

`Get-AppServiceAllPossibleOutboundPublicIps()`
Purpose: Show the App Service's possible outbound public IPs, which can be used to create Azure Key Vault network access rules.
Parameters: SubscriptionId, ResourceGroupName, AppServiceName

`Get-AppServiceAllCurrentOutboundPublicIps()`
Purpose: Show the App Service's current outbound public IPs. These will be a subset of all _possible_ outbound public IPs, so `Get-AppServiceAllPossibleOutboundPublicIps()` is the better function to use, but this is included for reference and comparison.
Parameters: SubscriptionId, ResourceGroupName, AppServiceName

`Set-KeyVaultPublicNetworkAccessEnabledForMe()`
Purpose: Adds a network access rule to the Key Vault for the public IP address which you are currently using. Also sets public network access enabled with default action Deny.
Parameters: SubscriptionId, ResourceGroupName, KeyVaultName

`Set-KeyVaultPublicNetworkAccessEnabledForIpAddresses()`
Purpose: Adds a network access rule to the Key Vault for each provided public IP address. Also sets public network access enabled with default action Deny.
Parameters: SubscriptionId, ResourceGroupName, KeyVaultName, PublicIpAddresses

`Set-KeyVaultPublicNetworkAccessEnabledForIpAddress()`
Purpose: Adds a network access rule to the Key Vault for the provided public IP address. Also sets public network access enabled with default action Deny.
Parameters: SubscriptionId, ResourceGroupName, KeyVaultName, PublicIpAddress

### Azure_Subscription_AuthZ_Remove_Deprecated_Accounts

`Get-DeletedUser()`
Purpose: Retrieves the recently deleted object from Microsoft Graph's deleted objects. Useful when trying to match a name to a deleted object ID (e.g. user or service principal GUID).
Parameters: SubscriptionId, DeletedObjectId

### Azure_Subscription_DP_Avoid_Plaintext_Secrets_Deployments

`Get-ResourceGroupDeployment()`
Purpose: Show the specified Azure Resource Group deployment (or list all if no deployment is specified by name). Useful to check for secrets on Deployment parameters.
Parameters: SubscriptionId, ResourceGroupName, DeploymentName

`Get-ResourceGroupDeploymentOperations()`
Purpose: Show the Azure Resource Group deployment's detailed operations.
Parameters: SubscriptionId, ResourceGroupName, DeploymentName

`Get-SubscriptionDeployments()`
Purpose: Show Azure Subscription deployments. Useful to check for secrets on Deployment parameters.
Parameters: SubscriptionId

`Get-SubscriptionDeploymentsAndOperations()`
Purpose: Show Azure Subscription deployments as well as detailed operations for each. Useful to check for secrets on Deployment parameters.
Parameters: SubscriptionId

### Azure_Subscription_SI_Dont_Use_B2C_Tenant

`Get-AzureADB2CTenants()`
Purpose: List all Azure AD B2C tenants deployed in the subscription.
Parameters: SubscriptionId

`Get-AzureADB2CResourceProvider()`
Purpose: Show the Azure AD B2C Resource Provider and its current registration state on the subscription.
Parameters: SubscriptionId

`Get-RegisteredResourceProviders()`
Purpose: List all Azure Resource Providers registered in the subscription.
Parameters: SubscriptionId

`Unregister-AzureADB2CResoureProvider()`
Purpose: Unregister the Azure AD B2C Resource Provider from the subscription.
Parameters: SubscriptionId

### Azure_VirtualMachine_SI_Enable_Antimalware

`Get-MDEPreferences()`
Purpose: Run on a VM to show current configuration preferences for Microsoft Defender for Endpoint.
Parameters: None

`Get-MDEStatus()`
Purpose: Run on a VM to show current status for Microsoft Defender for Endpoint.
Parameters: None

`Set-MDESignatureUpdateScheduledTask()`
Purpose: Run on a VM to create an hourly scheduled task to run Microsoft Defender for Endpoints signature update. Normally, this should not be needed, but can be useful when investigating possible signature update timing/scheduling issues.
Parameters: None
