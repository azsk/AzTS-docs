## DBForPostgreSQL

| ControlId | Dependent Azure API(s) and Properties | Control spec-let |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_DBforPostgreSQL_Audit_Enable_ATP<br><b>DisplayName:</b><br>Enable Threat detection for PostgreSQL<br><b>Description: </b><br> Advanced Threat Protection must be enabled for Azure Database for PostgreSQL |<b> ARM API to get security alert policy of a DBForPostgreSQL server: </b> <br> /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}<br>/providers/Microsoft.DBforPostgreSQL/servers/{serverName} <br> /securityAlertPolicies/Default?api-version=2017-12-01 <br><b>Properties:</b><br> properties.state| <b>Passed: </b><br>ATP is enabled and 'email notifications to admins' are also enabled.<br><b>Failed: </b><br>Either Postgre Sql is of 'basic tier' which does not support ATP. <br>Or ATP is disabled. <br>Or ATP is enabled but 'email notifications to admins' are disabled. |

