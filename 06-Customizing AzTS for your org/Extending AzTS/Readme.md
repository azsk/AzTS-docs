> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..

# Extending AzTS

## Contents
- [Add new control for existing SVT](Readme.md#steps-to-extend-the-control-svt) 
   - [Add new control by custom Azure policy](Readme.md#add-new-control-by-custom-azure-policy)
   - [Add new control by custom ASC Assessment](./Extending%20AzSK%20Module/Readme.md#add-new-control-by-custom-asc-assessment)
- [FAQ](Readme.md#faqs)  

----------------------------------------------

### Add new control for existing SVT
Azure Tenant Security Solution (AzTS) provides capability to add new controls(for existing services supported by AzTS) to customize the AzTS for your organization as per your need.
Currently you can extend AzTS controls set by either adding a new control based on custom Azure Policy or based on Azure Security Center assessment.

### Add new control by custom Azure policy
Please follow the below mentioned steps to add new controls based on custom Azure Policy:

Step 0: Prerequisites - TBD

Step 1: Assign the required policy definition to root management group of your tenant. To assign a policy definition, please follow the steps mentioned [here](https://docs.microsoft.com/en-us/azure/governance/policy/tutorials/create-and-manage#assign-a-policy).

Step 2: Get the ID of the policy definition and policy assignment. If you already have ID of policy definition and assignment handy, please go to step #3 directly or follow the below mentioned steps to get these details.

    1- Go to the Azure portal. Search for and select Policy.
        <Screenshot>
    2- Select Assignments on the left side of the Azure Policy page.
        <Screenshot>
    3- Change the Scope filter to required management group scope.
    4- Select the required assignment.
        <Screenshot>
    5- Copy the Assignement ID.
        <Screenshot>
    6- Click on View Definition.
        <Screenshot>
    7- Copy the Definition ID.
        <Screenshot>

Step 3: Go to AzTS UI. (Link to Faqs)

Step 4: Open Control editor tool.
    <Screenshot>

Step 5: Click on Action and select Add new control option.
    <Screenshot>

Step 6: Select the service/feature for which you want to add new control.
    <Screenshot>

Step 7: Select either one of the existing Security Domain for the control or if you want new Security Domain type required domain in text field.
    <Screenshot>

Step 8: Provide the Control ID. Initial part of the control ID is pre-populated based on the service/feature and secuirty domain you choose for the control (Azure_FeatureName_SecurityDomain_XXX).

    **Note:** Please don't use spaces between words instead use underscore '_' to separate words in control ID. 
    To see some of the examples of existing control IDs please check out this list.

Step 9: Set Control Scan Source to 'Policy'.

Step 10: 

