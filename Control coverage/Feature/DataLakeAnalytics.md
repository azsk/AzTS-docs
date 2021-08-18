## Data Lake Analytics

| ControlId | Dependent Azure API(s) and Properties | Control spec-let |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_DataLakeAnalytics_DP_Encrypt_At_Rest<br><b>DisplayName:</b><br>Data Lake Analytics sensitive data must be encrypted at rest<br><b>Description: </b><br> Sensitive data must be encrypted at rest | <b> ARM API to get the Data Lake Store accounts associated with the Data Lake Analytics account: </b> <br> /subscriptions/{subscriptionId}<br>/resourceGroups/{resourceGroupName}<br>/providers/Microsoft.DataLakeAnalytics<br>/accounts/{accountName}<br>?api-version=2016-11-01 <br><b>Properties:</b><br> properties.dataLakeStoreAccounts[\*].name <br><br><b> ARM API to get encryption state of associated Data Lake Store accounts: </b><br> /subscriptions/{subscriptionId}<br>/resourceGroups/{resourceGroupName}<br>/providers/Microsoft.DataLakeStore<br>/accounts/{accountName}<br>?api-version=2016-11-01 <br><b>Properties:</b><br> properties.encryptionState | <b>Passed: </b><br>Encryption is enabled.<br><b>Failed: </b><br>Encryption is disabled. |

