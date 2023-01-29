> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.
<br>

# AutoRemediation
This feature is not enabled by default. Below is the AzTS UI with AutoRemediation feature off by default:

![UIWithAutoRediationDisabled](../Images/04_DefaultUIWithAutoRemediationDisabled.png)

To enable this feature for your AzTS setup, please follow steps mentioned below:

- Open the [Azure portal](https://portal.azure.com/).
- Navigate to AzTS host subscription -> AzTS host resource group.
- Go to required AzTS API app service(AzSK-AzTS-WebApi-xxxxx).
- Go to Configuration under Settings.
- Click on "New application setting" to add required appsettings.
- Add **FeatureManagement__AutoRemediation** as the Name of the appsetting.
- Add **true** as the value of the appsetting.
- Add **RemediationFeatureConfiguration__IsEnabled** as the Name of the appsetting.
- Add **true** as the value of the appsetting.
- Add **UIConfigurations__RemediationFeatureConfiguration__IsEnabled** as the Name of the appsetting.
- Add **true** as the value of the appsetting.
![AddConfig](../Images/04_AddCofigForAutoRemediation.png)

Save these settings. This will restart AzTS API app service. 
Next time, when you open AzTS UI, you will see Remediation Mode toggle button.
![RemdiationMode](../Images/04_Autoremdiation_RemediationMode.png)

It is turned off on UI load by default. Currently only few controls are supported for AutoRemediation. You can find list for such controls [here](../Scripts/RemediationScripts/ControlsEligibleForRemediationThroughUI.md).

Once you turn on Remediation mode, you will get option to select failing controls(from above list available for remediation through UI). You can select multiple such failing controls and from Action button, download zipped folder containing scripts and other files necessary for remediation.Detailed steps about using this zip folder for remediation can be found [here](../Scripts/RemediationScripts/Instructions.pdf).

