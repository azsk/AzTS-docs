> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

<br/>

# **Authentication flow for AzTS REST APIs**

To use AzTS REST API one needs to submit a request-header that contains an access token. The access token is used for authentication and authorization. This document walks through several authentication flows using Microsoft Authentication Library (MSAL) for use in different application scenarios. You can use one of these approaches to generate access token. 

> _Note: Access token generated using the authentication flows listed below is intended to access AzTS API endpoints and not Azure subscriptions._

## Available options to acquire tokens

|Flow|Description|
|--|--|
|[Authorization code](./Authentication%20flow%20for%20AzTS%20REST%20APIs.md#authorization-code)|Used in apps that are installed on a device to gain access to protected resources, such as web APIs. Enables you to add sign-in and API access to your mobile and desktop apps.|
|[Client credentials](./Authentication%20flow%20for%20AzTS%20REST%20APIs.md#client-credentials)|Allows you to access web-hosted resources by using the identity of an application. Commonly used for server-to-server interactions that must run in the background, without immediate interaction with a user.|


# Authorization code

User authorization code flow uses user's credentials to generate the token. This is an interactive flow where user is prompted to enter Azure AD username and password. To generate token using this flow, you need to provide the **Tenant ID**, **Client ID** and **Scope**.

**Required Az Module**
``` PowerShell
Install-Module -Name MSAL.PS -AllowClobber -Scope CurrentUser -repository PSGallery
```

**Command to generate the token:**
``` PowerShell

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-app-id>' -RedirectUri 'https://localhost' -Scopes '<WebAPI-scope>'

```
|Parameter|Description|Required?|
|--|--|--|
|Tenant ID|Tenant identifier of the authority to issue token. It can also contain the value "consumers" or "organizations".|Yes|
|Client ID| You can either register a new application using the steps provided here<todo azure doc> or request the AzTS admin of your organization to provide the client ID of the centrally registered application for access AzTS REST APIs which the Admin must have created during the setup ([as mentioned here](README.md#setup-for-azts-admin-only)). | Yes |
| Scope | Scope of the WebAPI for which access token has to be generated. Please contact AzTS admin for the details ([as mentioned here](./README.md#setup-for-azts-admin-only)). | Yes|


# Client credentials

Client credential flow uses the client credentials (client id and client secret) to generate the token. This is a two-step process.

1. You will need to [register a new Azure AD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application) or use an existing AAD application and ask AzTS admin to provide permissions by following steps mentioned in [this FAQ](./Set%20up.md#an-end-user-wants-to-access-azts-rest-api-using-spn-credentials-ie-using-client-credential-authentication-flow-what-are-the-steps-to-grant-access-to-an-spnazure-ad-application-created-by-end-user-to-be-able-to-access-azts-rest-api).

2. Then use the following PowerShell command to generate access token. This token will be generated against specified Service Principal Name (SPN) and **SPN must have one of the following permissions at Azure subscription or resource group scope** to use AzTS APIs.

    - Owner
    - Contributor
    - ServiceAdministrator
    - CoAdministrator
    - AccountAdministrator
    - Security Reader
    - Security Admin

    <br>

**Command to generate the token:**
``` PowerShell
# Add client secret key of client app registration created in Step-1.
$ClientSecret = '<client-secret>' | ConvertTo-SecureString -AsPlainText -Force

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-id>' -ClientSecret $ClientSecret -Scopes "<WebAPI-scope>/.default"

```

|Parameter|Description|Required?|
|--|--|--|
|Tenant ID|Tenant identifier of the authority to issue token. It can also contain the value "consumers" or "organizations".|Yes|
|Client ID| Application (client) id of the AAD application created in step 1. | Yes |
|Client Secret| Client secret of the AAD application created in step 1. For steps to create a new client secret, refer [this page](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-credentials).|Yes|
| Scope | Scope of the WebAPI for which access token has to be generated. Please contact AzTS admin for the details ([as mentioned here](./README.md#setup-for-azts-admin-only)). | Yes|