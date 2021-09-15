> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..

<br/>

# **Authentication flow for AzTS REST APIs**

To use AzTS REST API one needs to submit a request-header that contains an access token. The access token is used for authentication and authorization. This document walks through several authentication flows using Microsoft Authentication Library (MSAL) for use in different application scenarios. You can use one of these approches to generate access token. 

> _Note: Access token generated using the authentication flows listed below is intented to access AzTS API endpoints and not Azure subscriptions._

## Available options to acquire tokens

|Flow|Description|
|--|--|
|[Authorization code]()|Used in apps that are installed on a device to gain access to protected resources, such as web APIs. Enables you to add sign-in and API access to your mobile and desktop apps.|
|[Client credentials]()|Allows you to access web-hosted resources by using the identity of an application. Commonly used for server-to-server interactions that must run in the background, without immediate interaction with a user.|


# Authorization code

User authorization code flow uses user's crediential to generate the token. This is an interactive flow where user is prompted to enter Azure AD username and password. To generate token using this flow, you need to provide the **Tenant ID**, **Client ID** and **Scope**.

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
|Client ID| You can either register a new application using the steps provided here<todo azure doc> or request the AzTS admin of your organization to provide the client ID of the centrally registered application for access AzTS REST APIs which the Admin must have created during the setup (step 3<todo link>). | Yes |
| Scope | Enter the scope of the WebAPI for which access token has to be generated. Please contact AzTS admin for the details.<todo link step 2> | Yes|


# Client credentials

## Step 1: App registration

For all the authentication flows listed in this page, one needs to register an AD application. After you have created the app registration note down the following details <todo link>: which has access at sub level.

1. Application (client) ID
2. Tenant ID