## Traffic Manager

| ControlId | Dependent Azure API(s) and Properties | Control spec-let |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br> Azure_TrafficManager_DP_Enable_HTTPS <br><b>DisplayName:</b><br>Traffic Manager profile should use HTTPS protocol for endpoint monitoring. <br><b>Description: </b><br> Traffic Manager profile should use HTTPS protocol for endpoint monitoring. |  <b> ARM API to lists all Traffic Manager profiles within a subscription: </b> <br> /subscriptions/{subscriptionId}/providers/Microsoft.Network/trafficmanagerprofiles?<br>api-version=2018-04-01 <br><b>Properties:</b><br> properties.endpoints[\*] <br> properties.monitorConfig.protocol | <b>Passed: </b><br> 1. No endpoints are present in the traffic manager profile. <br> 2. All endpoints are disabled <br> 3. Endpoints are enabled with HTTPS protocol. <br><b>Failed: </b><br> Endpoints are enabled without HTTPS protocol. <br><b>NotApplicable: </b><br> TCP protocol is enabled for endpoint monitoring. |

