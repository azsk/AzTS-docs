----------------------------------------------

> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..
# AzTS REST APIs 

### On this page:
- [Overview](README.md#overview)
- [Available APIs](README.md#available-apis)
- [Generate authentication token to access API endpoints](README.md#Generate-authentication-token-to-access-API-endpoints)
- [FAQs](README.md#FAQs)

-----------------------------------------------------------------
## Overview 
The Azure Tenant Security Solution (AzTS) provides APIs which can be leveraged to scan subscription(s) and get control scan result for subscription(s). This is alternative for AzTS UI to get insights about security compliance from AzTS perspective. 

This document will help you out with the following aspects:
1. Available API details:
    <br/>1.1 Request scan
    <br/>1.2 Get scan results
2. Generate authentication token to access API endpoints: <br/>
        2.1 Using client credential flow<br/>
        2.2 Using user authentication code flow<br/>
    
> **Note for AzTS admin:** This feature is disabled by default. To enable this feature and other pre-requisites, please refer [steps](Prerequisite%20Steps.md#prerequisites-steps)


## Available APIs:
|API|Description|
|----|----|
| [Request scan](README.md#11-request-scan---post) |Request ad-hoc scan for subscription(s).|
| [Get scan results](README.md#12-get-latest-scan-results---post) | Get scan results for a subscription.|


[Back to top…](README.md#On-this-page)

## Generate authentication token to access API endpoints
User has to generate authentication token in order to use AzTS APIs.
There are two ways to generate access tokens:
- Option 1: Using user authentication code flow
- Option 2: Using client credential flow


**Required Az Module**
``` PowerShell
Install-Module -Name MSAL.PS -AllowClobber -Scope CurrentUser -repository PSGallery
```
### Option 1: Using user authentication code flow
User authentication code flow uses user's crediential to generate the token.
> Note: You will need to contact AzTS admin to get `<client-app-id`> and `<WebAPI-scope`> required to generate token using this flow. 

**Command to generate the token:**
``` PowerShell

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-app-id>' -RedirectUri 'https://localhost' -Scopes '<WebAPI-scope>'

```
> Note: This token is intented to access AzTS API endpoints and not subscriptions.

[Back to top…](README.md#On-this-page)


### Option 2: Using client credential flow
Client crediential flow uses the client credentials (client id and client secret) to generate the token. You will need to register a new Azure AD application and ask AzTS admin to provide permissions by following steps mentioned over [here](README.md#what-are-the-permissions-required-to-use-azts-apis).AzTS admin will also provide scope of the WebAPI for which token has to be generated.
You can use following PowerShell command to generate access token. This token will be generated against specified SPN (Service Principal Name) and **SPN must have [required](README.md#what-are-the-permissions-required-to-use-azts-apis) access over the subscription** to use AzTS APIs.

**Command to generate the token:**
``` PowerShell
# Add client secret key of client app registration created in Step-1.
$ClientSecret = '<client-secret>' | ConvertTo-SecureString -AsPlainText -Force

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-id>' -ClientSecret $ClientSecret -Scopes "<WebAPI-scope>/.default"

```
> Note: This token is intented to access AzTS API endpoints and not subscriptions.

[Back to top…](README.md#On-this-page)


## FAQs

### How to get WebAPI URL with the help of AzTS admin?
1. Go to Azure Portal.
2. Go to **Resource Groups**.
3. Select your Resource Group where you have configured AzTS set up.
4. Select the App Service for API 'AzSK-ATS-WebAPI-xxxxx'.
5. In **Overview** section, copy **URL**.



### What are the permissions required to use AzTS APIs?
You must have permission over a subscription with any of the following role:
- Owner
- Contributor
- ServiceAdministrator
- CoAdministrator
- AccountAdministrator
- Security Reader
- Security Admin
> **Note:** If you have been recently granted access to a subscription, you would be access AzTS APIs after 24 hours as it takes 24 hours to refresh latest RBAC.

### What are the steps for AzTS admin to grant the permission for requested Client app?
1. Go to Azure Portal.
2. Go to **App Registration**.
3. Select WebAPI App Registration.
4. Go to **Add a client application**.
5. Add client id of request client app.
6. Enable the check box **Authorized scopes**.
7. Add application.
8. Copy scope from 'Scopes'.

[Back to top…](README.md#On-this-page)

## Feedback

For any feedback contact us at: aztssup@microsoft.com 

[Back to top…](README.md#On-this-page)