## Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server

### DisplayName 
[Enable advanced data security on your SQL servers](../../../Control%20coverage/Feature/SQLServer.md#azure_sqldatabase_audit_enable_threat_detection_server)

### Required Policies
Control can be covered with Azure policies mentioned below:
- Policy to enable Microsoft Defender with Standard tier for SQL servers at Subscription level (if not enabled).
- Policy to configure/audit email address in Microsoft Defender security contacts (if security contacts not setup as per requirements).
- Policy to audit/enforce Advanced Threat Protection (ATP) for each non-compliant SQL server.
- Policy to audit/enforce SQL auditing for each non-compliant SQL server.
- Policy to audit Security Alert contacts for SQL server (if security contacts not setup as per requirements).
___ 

#### Policy Details

Following policy can be used to audit/enforce SQL Auditing on SQL server.
 > **Important**: 
    1. Two different policy definitions are required to cover both general SQL servers and SQL servers which are part of Synapse Workspace as policy aliases are different.  
    2. In the provided resource group, Storage account will be created in each region where a SQL Server is created that will be shared by all servers in that region.
    3. Provided resource group should pre-exist in all the subscriptions (in scope), otherwise remediation will fail. 

#### Policy Definition
[Security - SQL Server - AuditSqlServerAuditingSettings](Security%20-%20SQL%20Server%20-%20AuditSqlServerAuditingSettings.json)
(Policy to audit the SQL Auditing on SQL Server.)

#### Parameter details
|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| AuditIfNotExists |No |


#### Policy Definition
[Security - SQL Server - DeploySqlServerAuditSettings](Security%20-%20SQL%20Server%20-%20DeploySqlServerAuditSettings.json)
(Policy to enforce the SQL Auditing on SQL Server.)

#### Parameter details
|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy | DeployIfNotExists |No |
| RetentionDays | The value in days of the retention period (0 indicates unlimited retention) | 365 |No |
| StorageAccountsResourceGroup | Resource group name for storage accounts | NA |Yes |


#### Policy Definition
[Security - SQL Server - Synapse SQL pools - DeploySqlServerAuditSettings](Security%20-%20SQL%20Server%20-%20Synapse%20SQL%20pools%20-%20DeploySqlServerAuditSettings.json)
(Policy to enforce the SQL Auditing on SQL Server which are part of Synapse Workspace.)

#### Parameter details
|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy | AuditIfNotExists |No |
| RetentionDays | The value in days of the retention period (0 indicates unlimited retention) | 365 |No |
| StorageAccountsResourceGroup | Resource group name for storage accounts | NA |Yes |
___ 


#### Policy Details

Following policy can be used to audit/enforce Advanced Threat Protection (ATP) for SQL server.

#### Policy Definition
[Security - SQL Server - AuditSqlServerThreatDetection](Security%20-%20SQL%20Server%20-%20AuditSqlServerThreatDetection.json)
(policy to audit ATP settings on SQL Server)

#### Parameter details
|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| AuditIfNotExists |No |

[Security - SQL Server - DeploySqlServerThreatDetection](Security%20-%20SQL%20Server%20-%20DeploySqlServerThreatDetection.json)
(policy to enforce ATP settings on SQL Server)

#### Parameter details
|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy | DeployIfNotExists |No |
| RetentionDays | The value in days of the retention period (0 indicates unlimited retention) | 365 |No |
| StorageAccountsResourceGroup | Resource group name for storage accounts | NA |Yes |

[Security - SQL Server - Synapse SQL pools - DeploySqlServerThreatDetection](Security%20-%20SQL%20Server%20-%20Synapse%20SQL%20pools%20-%20DeploySqlServerThreatDetection.json)
(policy to enforce ATP settings on SQL Server which are part of Synapse Workspace.)

#### Parameter details
|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy | AuditIfNotExists |No |

___ 

#### Policy Details

Following policy can be used to audit Security Alert contacts for SQL server.

#### Policy Definition
[Security - SQL Server - AuditSqlServerSecuritySettings](Security%20-%20SQL%20Server%20-%20AuditSqlServerSecuritySettings.json)

#### Parameter details
Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| AuditIfNotExists |No |

___ 


#### Policy Details

Following policy will enable Microsoft Defender with Standard tier for SQL servers at Subscription scope. This will help in creation of protected resources.

#### Policy Definition
[Security - Subscription - EnableMicrosoftDefenderForSQL](Security%20-%20Subscription%20-%20EnableMicrosoftDefenderForSQL.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy | DeployIfNotExists |No |

___ 

#### Policy Details

Following policy will configure/Audit security contacts (email) at Subscription scope.

#### Policy Definition
[Security - Subscription - UpdateSecurityContacts](Security%20-%20Subscription%20-%20UpdateSecurityContacts.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy | DeployIfNotExists |No |
| EmailAddress | Email address for security contact | NA |Yes|

___ 

#### Policy Assessment Evaluation

To collect the complete audit evaluation for a control, please run the policies in below order.

The assessment result should be a combination of:

1. [Security - SQL Server - AuditSqlServerAuditingSettings](Security%20-%20SQL%20Server%20-%20AuditSqlServerAuditingSettings.json)
2. [Security - SQL Server - AuditSqlServerThreatDetection](Security%20-%20SQL%20Server%20-%20AuditSqlServerThreatDetection.json)
3. [Security - SQL Server - AuditSqlServerSecuritySettings](Security%20-%20SQL%20Server%20-%20AuditSqlServerSecuritySettings.json) OR [Security - Subscription - UpdateSecurityContacts](Security%20-%20Subscription%20-%20UpdateSecurityContacts.json)
___ 


### Notes
1. It is recommended to assign the policy to audit the MDC security contacts configuration at Subscription scope (or Management group with subscriptions managed by the same team) as the policy will configure the same email address for all subscriptions in a given MG scope.
2. It is recommended to assign policy to enable SQL auditing at Subscription scope (or Management group with subscriptions managed by same team) as it will require one existing resource group (in all subscriptions in scope) at the time of policy assignment and a Storage account will be created in each region where a SQL Server is created that will be shared by all servers (in the subscription) in that region.