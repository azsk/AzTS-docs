## Redis Cache

| ControlId | Dependent Azure API(s) and Properties | Control spec-let |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_RedisCache_DP_Use_SSL_Port<br><b>DisplayName:</b><br>Non-SSL port must not be enabled.<br><b>Description: </b><br> Non-SSL port must not be enabled. | <b> ARM API to get all Redis caches in the specified subscription. </b> <br> /subscriptions/{subscriptionId}/providers/Microsoft.Cache/Redis? <br> api-version=2018-03-01 <br><b>Properties:</b><br> properties.enableNonSslPort| <b>Passed: </b><br> Non-SSL port is not enabled for Redis Cache. <br><b>Failed: </b><br> Non-SSL port is enabled for Redis Cache. |


