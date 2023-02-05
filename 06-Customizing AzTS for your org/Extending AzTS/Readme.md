> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

# Extending AzT
Azure Tenant Security Solution (AzTS) provides capability to add new controls(for existing services supported by AzTS) to customize the AzTS for your organization as per your need.
Currently you can extend AzTS controls set by either adding a new control based on custom Azure Policy or based on Microsoft Defender for Cloud assessment using Control Metadata Editor Tool. 

## Enabling Control Medatadata Editor tool
This feature is not enabled by default. To enable this feature for your AzTS setup, please follow steps mentioned [here](Prerequisites.md#prerequisite-azts-configurations-to-enable-control-medatadata-editor-toolcmet).

## Add new control for existing SVT

   - [Add new control based on custom Azure policy](AddControlForPolicy.md)
   - [Add new control based on MDC Assessment](AddControlForAssessment.md) 

## Update existing control metadata
   - [Update existing control metadata](UpdateControlMetadata.md)









