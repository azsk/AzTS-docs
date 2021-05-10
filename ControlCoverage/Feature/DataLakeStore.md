## Data Lake Storage

| ControlId | Dependent Azure API(s) and Properties | Control spec |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_DataLakeStore_DP_Encrypt_At_Rest<br><br><b>DisplayName:</b><br>Data Lake Store sensitive data must be encrypted at rest<br><br><b>Description: </b><br> Sensitive data must be encrypted at rest | <b> ARM API to get the specified Data Lake Store account: </b> <br> /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}? <br> api-version=2016-11-01 <br><br><b>Properties:</b><br> properties.encryptionState | <b>Scope: </b> Applies to all Azure DataLakeStore.<br><br><b>Config: </b> NA<br><br> <b>Passed: </b><br>Encryption is enabled.<br><br> <b>Failed: </b><br>Encryption is disabled. |

