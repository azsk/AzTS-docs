> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

</br>

# FAQs

- ### Setup
 1. [Getting error "Class keyword is not allowed in ConstrainedLanguage mode"](../00a-Setup/Readme.md#should-i-run-powershell-ise-as-administrator-or-regular-user)
 2. [How to disable AzTS scan and uninstall the setup"](#how-to-disable-azts-scan-and-uninstall-the-setup? )
3. [How to add new subscriptions/mangement groups after deploying AzTS"](../00a-Setup/Readme.md#should-i-run-powershell-ise-as-administrator-or-regular-user)

- ### Monitoring
 1. [I am getting alert mail "AzTS MONITORING ALERT: AzTS Auto-Updater Failure Alert". What does it mean? How to stop/resolve this alert]()



--------------------------------------------------
</br>

## <b>FAQs </b>

 ### 1.<b>Getting error : Class keyword is not allowed in ConstrainedLanguage mode </b>
This error can be observed where PowerShell is running in ConstrainedLanguage mode. If local settings for LaguageMode cannot be modified for some reason, AzTa setup can be done using aletrnate options. One of the options be copying deployment files to Azure storage and running the whole deployment procedure within Cloud Shell. 

### 2. <b>How to disable AzTS scan and uninstall the setup? </b>
AzTS scans can be disabled by revoking reader access granted to scanner Managed Identity at individual subscription level.
To uninstall or rollback AzTS scaner setup, below steps can be performed:
  1. Revoke scanner MI reader permissions for subscription(s) 
  2. Delete Azure AD application for UI and WebAPI (if created during installtion)
  3. Delete AzTS resource group. 
</br>

### 3. <b>How to add new subscriptions/mangement groups after deploying AzTS? </b>
You just need to provide reader access to scanner Managed Identity at subscription or Management Group level. From next schedule, AzTS will pick up new subscriptions for scanning. 

### 4. <b>I am getting alert mail "AzTS MONITORING ALERT: AzTS Auto-Updater Failure Alert". What does it mean? How to stop/resolve this alert? 
</b>
Auto updater runs daily and check for any updates available or not, if there are no updates it will not raise any alert or error. Alert mail "AzTS MONITORING ALERT: AzTS Auto-Updater Failure Alert" mostly indicates Auto updater function is not able to complete its job successfully in past runs.

To get more details about reason behind Autoupdate failure:
1.	Please check  if there any exceptions logged in Application Insight (AzSK-AzTS-AppInsights-xxxxx) by running following query:
exceptions
| where timestamp > ago(3d)
| where operation_Name =~ "AutoUpdater"
| order by timestamp desc
 
2.	If there are no exceptions, then please check  traces of the Job in Application Insight (AzSK-AzTS-AppInsights-xxxxx) by running following query:
traces
| where timestamp > ago(3d)
| where operation_Name =~ "AutoUpdater"
| order by timestamp desc
| project timestamp, message, severityLevel

If you see traces "Exception occurred in UpdateFunctionApp function while updating [AzSK-AzTS-UI-xxxxx]. Exception : [System.Exception: App service [AzSK-AzTS-UI-xxxxx] request to swap slot with production failed", then Auto-Updater is failing as staging and production slot swapping is failing for AzTS UI.You can disable the slot swap feature in Auto Updater with below steps:
1. Go to Auto Updater Function App (AzSK-AzTS-AutoUpdater-b93ac)
2. Configurations  Application Settings 
3. Click on add new Application Settings 
4. And setting with following Name and Value,
Name: HostEnvironmentDetails__AutoUpdateConfig__3__DeploymentSlotId
Value: production
5. Select ‘Deployment Slot Setting’ and save.
 
 
The above steps should stop this recurring alert, please validate after 24 hours using the same queries.


