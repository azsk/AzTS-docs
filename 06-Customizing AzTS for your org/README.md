> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

# Extending AzTS

## Customizing AzTS for your org

### Control Medatadata Editor tool
CMET (Control Metadata Editor Tool) is a tool that can be used by privileged users (mostly by admins maintaining AzTS setup for organization)to customize AzTS for organization. It provides capabilities to update control metadata (Tags, Display Name, control settings(if applicable)), enable or disable control, etc.
This feature is disabled by default. To enable this feature for your AzTS setup, please follow steps mentioned [here](../06-Customizing%20AzTS%20for%20your%20org/Extending%20AzTS/Prerequisites.md#prerequisite-azts-configurations-to-enable-control-medatadata-editor-tool).

CMET (Control metadata editor tool) is only accessible to privileged users based on AzTS API configurations. Please follow the steps mentioned [here](../06-Customizing%20AzTS%20for%20your%20org/Extending%20AzTS/Prerequisites.md#access-to-cmet-control-metadata-editor-tool) to add yourself as privileged user.(This is only required once per user).

Once CMET is enabled, you can use below features:

   - [Add new control based on custom Azure policy](/06-Customizing%20AzTS%20for%20your%20org/Extending%20AzTS/AddControlForPolicy.md)
   - [Add new control based on MDC Assessment](/06-Customizing%20AzTS%20for%20your%20org/Extending%20AzTS/AddControlForAssessment.md) 
   - [Update control metadata for existing control](../06-Customizing%20AzTS%20for%20your%20org/Extending%20AzTS/UpdateControlMetadata.md)

If you are looking for updating multiple controls at once, please follow steps mentioned [here](../06-Customizing%20AzTS%20for%20your%20org/Extending%20AzTS/FeaturesInCMET.md#bulk-edit)
   









