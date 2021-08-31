## Kubernetes Service

| ControlId | Dependent Azure API(s) and Properties | Control spec-let |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_NotificationHub_AuthZ_Dont_Use_Manage_Access_Permission	<br><b>DisplayName:</b><br>Access policies on Notification Hub must not have Manage access permissions.<br><b>Description: </b><br> Access policies on Notification Hub must not have Manage access permissions. | <b> ARM API to get Authorization rules: </b> <br> /subscriptions/{subsriptionId}/resourceGroups/{REsourcegroupName}/providers/Microsoft.NotificationHubs/namespaces/{NamespaceName}/notificationHubs/{NotificationHubName}/AuthorizationRules?api-version=2016-03-01 <br><b>Properties:</b><br> properties.rights<br>name<br> | <b>Passed: </b><br> No authorization rule Found with manage permission. <br><b>Verify: </b><br>Authorization rules found with manage permission.|
