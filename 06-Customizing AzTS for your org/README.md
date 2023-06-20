> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

# Extending AzTS
Azure Tenant Security Solution (AzTS) provides capability to add new controls (for existing services supported by AzTS) to customize the AzTS for your organization as per your need.
Currently you can extend AzTS controls set by either adding a new control based on custom Azure Policy or based on Microsoft Defender for Cloud assessment using Control Metadata Editor Tool. 
You can also update existing controls metadata like Display Name, Description, Tags etc.

## Enabling Control Medatadata Editor tool
Control Medatadata Editor tool (CMET) is required to extend AzTS. This feature is not enabled by default. To enable this feature for your AzTS setup, please follow steps mentioned [here](Extending AzTS/Prerequisites.md#prerequisite-azts-configurations-to-enable-control-medatadata-editor-toolcmet).

## Add new control for existing services

   - [Add new control based on custom Azure policy](AddControlForPolicy.md)
   - [Add new control based on MDC Assessment](AddControlForAssessment.md) 

## Update existing control metadata
   - [Update existing control metadata](UpdateControlMetadata.md)









