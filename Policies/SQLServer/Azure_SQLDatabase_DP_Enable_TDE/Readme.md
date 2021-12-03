## Azure_SQLDatabase_DP_Enable_TDE 

### DisplayName 
[Enable Transparent Data Encryption on SQL databases](../../../Control%20coverage/Feature/SQLServer.md#azure_sqldatabase_dp_enable_tde)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used to enable Transparent Data Encryption on non-compliant SQL databases.

    > **Important**: Two different policy definitions are required to cover both general SQL databases and SQL databases which are part of Synapse Workspace as policy aliases are different.  
    
#### Policy Definition
[Security - SQL DB - DeploySqlDBTransparentDataEncryption](Security%20-%20SQL%20DB%20-%20DeploySqlDBTransparentDataEncryption.json)

[Security - SQL DB - Synapse SQL pools - DeploySqlDBTransparentDataEncryption](Security%20-%20SQL%20DB%20-%20Synapse%20SQL%20pools%20-%20DeploySqlDBTransparentDataEncryption.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | Enable or disable the execution of the policy | DeployIfNotExists |No |


### Notes
NA







