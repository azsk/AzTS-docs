### IMPORTANT NOTE: Recently we have observed some issues related to AzTS setup due to which function apps inside AzTS setup lack function definition. If you are also facing the same issue, you need to re-run [setup command](00a-Setup#setting-up-azure-tenant-security-solution---step-by-step) with same parameter.
----------------------------------------------

> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..
# Azure Tenant Security Solution (AzTS) 


### Contents
- [Overview](README.md#overview)
- [Why Azure Tenant Security Solution?](README.md#why-azure-tenant-security-solution)
- [Feedback](README.md#feedback)

-----------------------------------------------------------------
## Overview 
The Azure Tenant Security Solution (AzTS) from the AzSK team can be used to obtain visibility to cloud subscriptions and resource configuration across multiple subscriptions in an enterprise environment. The AzTS is a logical progression of DevOps Kit which helps us move closer to an implementation of cloud security compliance solution using native security capabilities in Azure platform that are available today. Functionally, it is similar to running AzSK Continuous Assurance (CA) in central-scan mode.

## Why Azure Tenant Security Solution?
The AzTS Solution was created with the following explicit objectives (some of which were harder to accomplish using the existing Automation-based Continuous Assurance approach):
 * Ability to scan large number of subscriptions in a central scan model in a cost-effective and time-efficient manner
 * Being able to scale scanning capability up or down without externally imposed constraints (e.g., runbook memory, runtime limits)
 * Speeding up our effort to transition to native features (being able to respond to changes in Azure more rapidly and deploy modifications to controls)
 * Enable incremental transition of our controls from custom code to Azure/ASC policy-based approach (using ASC/policy-based controls where available today and continue to migrate as more controls become available)

[Back to top…](README.md#contents)

## Feedback

For any feedback contact us at: aztssup@microsoft.com 
