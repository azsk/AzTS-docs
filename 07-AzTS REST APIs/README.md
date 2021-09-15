> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..

<br/>

# Getting Started with the AzTS REST API 

## Introduction

The Azure Tenant Security Solution (AzTS) provides REST APIs which can be leveraged to scan subscription(s) and get control scan result for subscription(s). This is alternative for AzTS UI to get insights about security compliance from AzTS perspective. 

## Set up (For AzTS Admin Only)

> _Note: This step has to be performed by AzTS Admin._

The AzTS REST API feature is disabled by default in AzTS. To enable this feature for your end-users and other set up steps, please follow [this guide](Set%20up.md).

Please note that as an admin of AzTS Soln, you need to share the following information with the consumer/end-users of the AzTS REST API:

1. Scope of the AzTS REST API configured in the [step 2](Set%20up.md#step-2-of-4-steps-to-configure-azts-webapis-azure-active-directory-aad-application-to-access-azts-rest-api) of the set up steps.
2. Application (client) ID of the AAD application registered in [step 3](Set%20up.md#step-3-of-4-optional-register-an-fresh-azure-active-directory-aad-application-to-access-azts-rest-api) of the set up steps.
3. URL of the AzTS REST API copied in [step 4](Set%20up.md#step-3-of-4-optional-register-an-fresh-azure-active-directory-aad-application-to-access-azts-rest-api) of the set up step.
4. Tenant ID


## Available REST APIs

<br> 

Operation Group: Scan Result

|API|Description|
|----|----|
| [Request scan](./Scan%20Result%20APIs/Request%20Scan.md#request-scan---post) |Request ad-hoc scan for subscription(s).|
| [Get scan results](./Scan%20Result%20APIs/Get%20Scan%20Results.md#get-scan-results---post) | Get scan results for a subscription.|

## Feedback

For any feedback contact us at: aztssup@microsoft.com 