## Container Registry

| ControlId | Dependent Azure API(s) and Properties | Control spec |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_ContainerRegistry_AuthZ_Disable_Admin_Account<br><br><b>DisplayName:</b><br>The Admin account in Container Registry should be disabled.<br><br><b>Description: </b><br> The Admin account in Container Registry should be disabled. | <b> ARM API to lists all the container registries<br> under the specified subscription. </b> <br> /subscriptions/{subscriptionId}/providers<br>/Microsoft.ContainerRegistry/registries? <br> api-version=2019-05-01 <br><br><b>Properties:</b><br> properties.adminUserEnabled | <b>Scope: </b> Applies on all container registry resources.<br><br><b>Config: </b> NA<br><br> <b>Passed: </b><br> 'Admin User' is 'Disabled'. <br><br> <b>Failed: </b><br> 'Admin User' is 'Enabled'. |


