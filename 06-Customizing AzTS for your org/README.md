> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..


### [Overview](README.md#overview-1)
 - [When and why should I set up org policy?](README.md#when-and-why-should-i-setup-org-policy)
 <!-- - [How does AzTS use online policy?](README.md#how-does-azts-use-online-policy) -->

### [Setting up org policy](README.md#setting-up-org-policy-1)
 <!-- - [What happens during org policy setup?](Readme.md#what-happens-during-org-policy-setup) -->
 <!-- - [First-time policy setup - an example](Readme.md#first-time-policy-setup---an-example) -->
 
<!-- ### [Consuming custom org policy](Readme.md#consuming-custom-org-policy-1)

 - [Running scan in AzTS-UI with org policy](Readme.md#1-running-scan-in-local-machine-with-custom-org-policy)
 - [Running Tenant Scan with org policy](Readme.md#2-setup-continuous-assurance) -->
 
### [Modifying and customizing org policy](README.md#modifying-and-customizing-org-policy-1)
 <!-- - [Know more about controls](Readme.md#know-more-about-controls) -->
 - [AzTS UI CMET Tool](README.md#1-azts-ui-cmet-tool)
     - [Getting Started](README.md#getting-started)
     - [Basic scenarios for org policy customization:](README.md#basic-scenarios-for-org-policy-customization)
        - [Changing control setting](./AzTS_CMET_Tool_Scenarios/ChangeControlSetting.md)
        - [Customizing specific controls for a service SVT](./AzTS_CMET_Tool_Scenarios/CustomizeSpecificControls.md)
        - [Setting up and updating baselines for your org](./AzTS_CMET_Tool_Scenarios/SettingUpdatingBaseline.md)
     - [Advanced scenarios for org policy customization:](README.md#advanced-scenarios-for-org-policy-customization) 
        - [Add new control based on ASC Assessment evaluation](./AzTS_CMET_Tool_Scenarios/AddControlForAssessment.md)
        - [Add new control based on custom Azure Policy evaluation](./AzTS_CMET_Tool_Scenarios/AddControlForPolicy.md)
        - [Update/extend existing control by custom ASC Assessment](./AzTS_CMET_Tool_Scenarios/CustomizeASCControls.md) 
        - [Update/extend existing control by custom Azure policy](./AzTS_CMET_Tool_Scenarios/CustomizeCustomPolicyControls.md)
     
 - [Extend AzTS Solution](README.md#2-extend-azts-solution)
     - [Getting Started](README.md#getting-started-1)
     - [Basic scenarios for org policy customization:](README.md#basic-scenarios-for-org-policy-customization-1)
        - [Update default metadata (display name, recommendation, etc.) for existing controls](./Extend_AzTS_Soln_Scenarios/UpdateDefaultMetadata.md)<br>
        - [Changing control setting for existing controls](./Extend_AzTS_Soln_Scenarios/ChangeControlSetting.md)<br>
        - [Update control metadata for controls based on ASC Assessment](./Extend_AzTS_Soln_Scenarios/UpdateControlMetadataASCAssessment.md)<br>
        - [Customizing specific controls for an existing service](./Extend_AzTS_Soln_Scenarios/CustomizeSpecificControls.md)<br>
     - [Advanced scenarios for org policy customization:](README.md#advanced-scenarios-for-org-policy-customization-1) 
        - [Update/extend existing control by custom Azure policy](./Extend_AzTS_Soln_Scenarios/CustomizeControlEvaluator.md)<br>
        - [Update/extend existing control by custom ASC Assessment](./Extend_AzTS_Soln_Scenarios/CustomizeASCControls.md) <br>
        - [Add new control for existing service](./Extend_AzTS_Soln_Scenarios/AddNewControl.md)<br>
     

# Overview

## When and why should I setup org policy

When you run any scan command from AzTS (using AzTS-UI or scheduled scan), it relies on JSON-based policy files to determine various parameters that effect the behavior of the scan it is about to run. These policy files are downloaded 'on the fly' from a policy server. When you run the public version of the scanner, the offline policy files present in the AzTS solution/package are accessed. Thus, whenever you run a scan from a vanilla installation, AzTS accesses the offline file present in the package to get the policy configuration and runs the scan using it.

The JSON inside the policy files dictate the behavior of the security scan. This includes things such as:
 - Which set of controls to evaluate?
 - What control set to use as a baseline?
 - What settings/values to use for individual controls? 
 - What messages to display for recommendations?
 <!-- - Add custom controls, Etc. -->

Note that the policy files needed for security scans are accessed from the last updated deployed AzTS package. 

While the out-of-box files in the package may be good for limited use, in many contexts you may want to "customize" the behavior of the security scans for your environment. You may want to do things such as: 
1. enable/disable some controls, 
2. change control settings to better match specific security policies within your org, 
3. change various messages,
4. modify existing control logic,
5. add additional filter criteria for certain regulatory requirements that teams in your org can leverage,
6. add new controls to existing service, etc.

When faced with such a need, you need a way to create and manage a dedicated policy endpoint customized to the needs of your environment. The organization policy customization setup feature helps you do that in an automated fashion.

In this document, we will look at how to setup an organization-specific policy endpoint, how to make changes 
to and manage the policy files and how to accomplish various common org-specific policy/behavior customizations 
for the AzTS.

<!-- ## How does AzTS use online policy? -->

# Setting up org policy

Basic org policy setup is done by default during AzTS installation. Setup leverages storage account (added along with AzTS setup) to hold various policy artifacts in the subscription. This should be a secure, limited-access subscription to be used only for managing your org's AzTS policy. There are few prerequisites which need to be completed to set up AzTS UI Control Metadata Editor Tool (CMET) for your AzTS Solution setup. Please follow the steps mentioned [here](./AzTS_CMET_Tool_Scenarios/Prerequisites.md).

<!-- ## What happens during org policy setup? -->
<!-- ## First-time policy setup - an example -->

# Modifying and customizing org policy

There are mainly two approaches to achieve org policy customization. Click on respective link based on scenario. </br>

## 1. AzTS UI CMET Tool:
AzTS UI Control Metadata Editor Tool (CMET) provides easy way to accomplish org policy customization. AzTS admin can use this feature in UI and perform control updates or addition of new controls with typical scenarios listed below.

### **Getting Started**

The typical workflow for all policy changes and customizatio will remain same and will involve the following basic steps:

1. Go to **AzTS UI**. (To get AzTS UI URL, check this [FAQ](https://github.com/azsk/AzTS-docs/blob/main/03-Running%20AzTS%20solution%20from%20UI/README.md#frequently-asked-questions))
2. Open **Control Metadata editor tool**.
![Open CMET Editor](../Images/06_ExtendingAzTS_Open_CMET.png)
3. Select one control.
4. Edit one or more control property.
5. **Save** and **Queue** the changes.
6. Go to scan tool of **AzTS UI**.
7. Trigger Adhoc scan.
8. Verify the changes done in step #4 are getting reflected in latest scan.


### **Basic scenarios for org policy customization**
[1. Changing control setting](./AzTS_CMET_Tool_Scenarios/ChangeControlSetting.md)<br>
[2. Customizing specific controls for a service SVT](./AzTS_CMET_Tool_Scenarios/CustomizeSpecificControls.md)<br>
[3. Setting up and updating baselines for your org](./AzTS_CMET_Tool_Scenarios/SettingUpdatingBaseline.md)<br>

### <b>Advanced scenarios for org policy customization</b>
[1. Add new control based on ASC Assessment evaluation](./AzTS_CMET_Tool_Scenarios/AddControlForAssessment.md)<br>
[2. Add new control based on custom Azure Policy evaluation](./AzTS_CMET_Tool_Scenarios/AddControlForPolicy.md)<br>
[3. Update/extend existing control by custom ASC Assessment](./AzTS_CMET_Tool_Scenarios/CustomizeASCControls.md) <br>
[4. Update/extend existing control by custom Azure policy](./AzTS_CMET_Tool_Scenarios/CustomizeCustomPolicyControls.md)<br>

## 2. Extend AzTS Solution:
AzTS Solution is published as NuGet package. This NuGet package comes with extensibility feature and this enables powerful capability for organization to customize the control behaviour with custom logic. 

### **Getting Started**

The typical workflow to achieve any listed scenarios will remain same and will involve the following basic steps:
1. Set up the AzTS Extended solution following the steps mentioned [here](./Extend_AzTS_Soln_Scenarios/SettingUpSolution.md). 
2. Modify or Author control metadata (JSON files).
3. Modify or Author control methods in respective control evaluator files.
4. Build and run the solution in your local system and verify your changes.

You will be able to achieve all scenarios listed using AzTS UI along with the following additional scenarios:

### <b>Basic scenarios for org policy customization</b>

In this section let us look at typical scenarios in which you would want to customize the org policy and ways to accomplish them.

[1. Update default metadata (display name, recommendation, etc.) for existing controls](./Extend_AzTS_Soln_Scenarios/UpdateDefaultMetadata.md)<br>
[2. Changing control setting for existing controls](./Extend_AzTS_Soln_Scenarios/ChangeControlSetting.md)<br>
[3. Update control metadata for controls based on ASC Assessment](./Extend_AzTS_Soln_Scenarios/UpdateControlMetadataASCAssessment.md)<br>
[4. Customizing specific controls for an existing service](./Extend_AzTS_Soln_Scenarios/CustomizeSpecificControls.md)<br>
<!-- #### Setting up and updating baselines for your org --> 

### <b>Advanced scenarios for org policy customization</b>

It is powerful capability of AzTS to enable an org to customize the control behaviour. You will be able to achieve the following scenarios:

[1. Update/extend existing control by custom Azure policy](./Extend_AzTS_Soln_Scenarios/CustomizeControlEvaluator.md)<br>
[2. Update/extend existing control by custom ASC Assessment](./Extend_AzTS_Soln_Scenarios/CustomizeASCControls.md) <br>
[3. Add new control for existing service](./Extend_AzTS_Soln_Scenarios/AddNewControl.md)<br>
4. Add new service altogether (non-existing service) - Coming soon!
<br>


