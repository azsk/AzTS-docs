## Container Registry

| ControlId | Dependent Azure API(s) and Properties | Control spec-let |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_ContainerRegistry_AuthZ_Disable_Admin_Account<br><b>DisplayName:</b><br>The Admin account in Container Registry should be disabled.<br><b>Description: </b><br> The Admin account in Container Registry should be disabled. | <b> ARM API to lists all the container registries under the specified subscription. </b> <br> /subscriptions/{subscriptionId}/providers/Microsoft.ContainerRegistry/registries? <br> api-version=2019-05-01 <br><b>Properties:</b><br> properties.adminUserEnabled | <b>Passed: </b><br> 'Admin User' is 'Disabled'. <br><b>Failed: </b><br> 'Admin User' is 'Enabled'. |


