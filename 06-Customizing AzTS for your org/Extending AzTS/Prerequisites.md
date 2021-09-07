# Add new control for existing SVT
Azure Tenant Security Solution (AzTS) provides capability to add new controls(for existing services supported by AzTS) to customize the AzTS for your organization as per your need.
Currently you can extend AzTS controls set by either adding a new control based on custom Azure Policy or based on Azure Security Center assessment.

## Prerequisite AzTS configuration to add new control
Below mentioned configuration is required before adding new control:

### AzTS API

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__AddNewControl -> true
- FeatureManagement__PolicyStates -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsAddNewControlEnabled -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsEnabled -> true
- WorkItemProcessorSettings__AppName -> work item processor web app name
- WorkItemProcessorSettings__HostResourceGroupName -> AzTS solution host resource group name
- WorkItemProcessorSettings__HostSubscriptionId -> AzTS solution host subscription id

### AzTS MetaDataAggregator

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

### AzTS WorkItemProcessor

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true