## Redis Cache

| ControlId | Dependent Azure API(s) and Properties | Control spec |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_RedisCache_DP_Use_SSL_Port<br><br><b>DisplayName:</b><br>Non-SSL port must not be enabled.<br><br><b>Description: </b><br> Non-SSL port must not be enabled. | <b> ARM API to get all Redis caches in the specified subscription. </b> <br> /subscriptions/{subscriptionId}/providers/Microsoft.Cache/Redis? <br> api-version=2018-03-01 <br><br><b>Properties:</b><br> properties.enableNonSslPort| <b>Scope: </b> Applies to all Azure Radis Cache.<br><br><b>Config: </b> NA<br><br> <b>Passed: </b><br> Non-SSL port is not enabled for Redis Cache. <br><br> <b>Failed: </b><br> Non-SSL port is enabled for Redis Cache. |


