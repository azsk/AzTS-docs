----------------------------------------------

> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..
# On Demand Scan using API 

### On this page:
- [Overview](README.md#overview)
- [Prerequisites](README.md#prerequisites-For-AzTS-admin)
- [Register an application in Azure AD to represent a client application](README.md#Step-1:-Register-an-application-in-Azure-AD-to-represent-a-client-application)
- [Generate user authentication token to access subscriptions](README.md#Generate-user-authentication-token-to-access-subscriptions)
- [API to scan a subscription](README.md#API-to-scan-a-subscription)
- [API to get control scan result](README.md#API-to-get-control-scan-result)
- [Feedback](README.md#Feedback)

-----------------------------------------------------------------
## Overview 
The Azure Tenant Security Solution (AzTS) provides APIs for users to allow on demand scan for a subscription and get control scan result.

This document will walk you through:
1. Register an application in Azure AD to represent a client application.
2. Configure permissions for WebAPI app registration.
3. Get administrator consent for WebAPI app registration.
4. Generate authentication token to access subscriptions.
    - Using client credential flow
    - Using user authentication code flow
5. API Operation Groups
    - Request for scan
    - Get control scan result

## Prerequisites (For AzTS admin)
Admin has to enable the flag **FeatureManagement__OnDemandScanAPI** in order to provide access over API endpoints.
How to enable 'OnDemandScanAPI' from Azure Portal:
1. Go to Azure Portal.
2. Go to **Resource Groups**.
3. Select your Resource Group where you have configured AzTS set up.
4. Select the App Service for API 'AzSK-ATS-API-xxxxx'.
5. Go to **Configuration**.
6. Set **FeatureManagement__OnDemandScanAPI** as true.
7. Save.

[Back to top…](README.md#On-this-page)

## Step 1: Register an application in Azure AD to represent a client application
Before generating the token or making an API call, client app registration needs to be created.
</br>
Follow below steps to create client application:
1. Go to the Azure portal to register your application.

2. Search for and select **App registrations**.

3. Select **New registration**.

4. When the **Register an application** page appears, enter your application's registration information:

    - In the **Name** section, enter a meaningful application name that will be displayed to users of the app, such as client-app.

    - In the **Supported account types** section, select **Accounts in any organizational directory (Any Azure AD directory - Multitenant)**.

5. In the **Redirect URI** section, select 'Web' and leave the URL field empty for now.

6. Select **Register** to create the application.

7. On the app **Overview** page, find the **Application (client) ID** value and record it for later.

8. Create a client secret for this application to use in a subsequent step (only if you want to use 'Client credential flow' to generate the token).

    - From the list of pages for your client app, select **Certificates & secrets**, and select **New client secret**.

    - Under **Add a client secret**, provide a **Description**. Choose when the key should expire, and select **Add**.

9. When the secret is created, note the key value for use in a subsequent step.

</br>

[Back to top…](README.md#On-this-page)

<!-- TBD: This token is not access subs, but to access AzTS REST API endpoints -->

## Step 2: Configure permissions for WebAPI app registration
1. Go to Azure Portal.
2. Go to **App Registration**.
3. Select your WebAPI App Registration.
4. Go to **API Permissions**.
5. Select **Add a permission**.
6. Go to **APIs my organization uses**.
7. Search your WebAPI client id and select.
8. Select **Delegated permissions**.
9. Select permissions.
10. **Add permissions**.

[Back to top…](README.md#On-this-page)

## Step 3: Get administrator consent for WebAPI app registration
If 'User consent' is restricted to the WebAPI, then WebAPI must have 'Admin consent' granted to expose the APIs.
Grant admin consent for client app registration:
1. Go to Azure Portal.
2. Go to **App Registration**.
3. Select your WebAPI App Registration.
4. Go to **API Permissions**.
5. Select **Add a permission**.
6. Click **Grant admin consent** for your Tenant.

[Back to top…](README.md#On-this-page)

## Step 4: Generate authentication token to access subscriptions
User has to generate authentication token in order to use APIs for any subscription.
There are two ways to generate access tokens:
- Option 1: Using client credential flow
- Option 2: Using user authentication code flow

#### Required Az Module
``` PowerShell
Install-Module -Name MSAL.PS -AllowClobber -Scope CurrentUser -repository PSGallery
```

### Option 1: Using client credential flow
Client crediential flow uses the client credentials (client id and client secret) to generate the token. Token will be generated against specified SPN (Service Principal Name) and **SPN must have [required](README.md#Required-roles) access over the subscription** to scan or to get the control scan result.

**Steps for 'WebAPI Owner' to grant the permission for requested Client app:**
1. Go to Azure Portal.
2. Go to **App Registration**.
3. Select WebAPI App Registration.
4. Go to **Add a client application**.
5. Add client id of request client app.
6. Enable the check box **Authorized scopes**.
7. Add application.
8. Copy scope from 'Scopes'.


> In order to generate the token for APIs, you have to get access for the client application from WebAPI owner.
> 1. Send the client id to WebAPI owner to request access for client application.
> 2. WebAPI owner will grant the access and share the scope.
> 3. Use WebAPI scope while generating the access token.


**Command to generate the token:**
``` PowerShell
# Add client secret key of client app registration created in Step-1.
$ClientSecret = '<client-secret>' | ConvertTo-SecureString -AsPlainText -Force

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-id>' -ClientSecret $ClientSecret -Scopes "<WebAPI-scope>/.default"

```

[Back to top…](README.md#On-this-page)

### Option 2: Using user authentication code flow
User authentication code flow uses user's crediential to generate the token. User must have access over the subscription  to scan or to get the control scan result.


**Command to generate the token:**
``` PowerShell

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-app-id>' -RedirectUri 'https://localhost' -Scopes '<WebAPI-scope>'

```

[Back to top…](README.md#On-this-page)

### Required roles:
You must have permission over a subscription with any of the following role:
- Owner
- Contributor
- ServiceAdministrator
- CoAdministrator
- AccountAdministrator
- Security Reader
- Security Admin
> **Note:** You need to run RBAC after granting the permission to SPN over subscription.

[Back to top…](README.md#On-this-page)

## Step 5: API Operation Groups
|Operation group|Description|
|----|----|
| [Request for scan](README.md#Request-for-scan) |Take subscription(s) for adhoc scan.|
| [Get control scan result](README.md#Get-control-scan-result) |Get control scan result for specified subscription.|


## Request for scan
Take list of subscription id(s) for adhoc scan.

## Description
To scan a subscription, you can pass list of subscription id(s). This API will return metadata about the status of subscription including 'Scan Request Id'. This 'Scan Request Id' can be further use to [get latest control scan result](README.md#Get-control-scan-result).


``` PowerShell
POST https://<WebAPI-URL>/adhocscan/RequestScan
```

### Steps for WebAPI owner to get WebAPI URL
1. Go to Azure Portal.
2. Go to **Resource Groups**.
3. Select your Resource Group where you have configured AzTS set up.
4. Select the App Service for API 'AzSK-ATS-API-xxxxx'.
5. In **Overview** section, take **URL**.

> Note: If you are not an admin, please contact with the admin to get WebAPI URL.

## Request Header
``` PowerShell
$header = "Bearer " + $token.AccessToken

$headers = @{"Authorization"=$header;"Content-Type"="application/json";}
```

## Request Body
``` PowerShell

$requestBody = @{"SubscriptionIDList"=@("{subscriptionId1}","{subscriptionId2}",...);}
```


**Request body parameter details:**
|Param Name|Description|Required?
|----|----|----|
| SubscriptionId| List of subscription id(s) for scan. | Yes|


## Sample Response
``` PowerShell
subscriptionID : {subscriptionId}
jobID          : 20210101074331
queueStatus    : Processing
message        : Subscription added to the queue
timeSpan       : 01/01/2021 7:43:31 AM
scanRequestId  : 20210101074331
```

> **Note:** 
> </br>
> 1. On demand scan for each subcription can be requested maximum 10 times in a day.
> 2. Use **scanRequestId** to get latest control scan result.



[Back to top…](README.md#On-this-page)

## Get control scan result
Return list of control scan result for specified subscription.

## Description
To get control scan result, you can pass subscription id as part of API URI. Also, you can provide '[Scan Request Id](README.md#Sample-Response)' as part of request body to get the latest control scan result.


``` PowerShell
POST https://AzSK-AzTS-WebApi-xxxxx.azurewebsites.net/adhocscan/subscription/{subscriptionId}/ControlScanResult
```

## URI Parameters
|Name|Description|Required?|
|----|----|----|
| ScanRequestId | To get control scan result with respect to the scan request id. | Yes |

## Request Header
``` PowerShell
$header = "Bearer " + $token.AccessToken

$headers = @{"Authorization"=$header;"Content-Type"="application/json";}
```

## Request Body
``` PowerShell
$requestBody = @{}
# Example:
$requestBody = @{"scanRequestId"="{scanRequestId}";"ControlIdList"=@("control_id1","control_id1");"ResourceNameList"=@("resource1","resource2");}
```

**Request body parameter details:**
|Param Name|Description|Required?
|----|----|----|
| ScanRequestId | To get control scan result with respect to the scan request id. | Yes |
| ControlIdList| List of control ids to get control result only for specific controls.| No |
| ResourceNameList | List of resources to get control result only for certain resources.| No |


> **Note:**
> </br>
> 1. If 'requestBody' is empty then API will return latest control scan result.
> 2. You can get entire control scan result only for one subscription at a time.

[Back to top…](README.md#On-this-page)

``` PowerShell

```

Sample PowerShell command:

``` PowerShell

$apiResponse = Invoke-WebRequest -Method POST -Uri '<API-URI>' -Headers $headers -Body ($requestBody | ConvertTo-Json) -UseBasicParsing

$response = ConvertFrom-Json $apiResponse.Content

$response

# Storing control scan result in json file.
$folderPath = [Environment]::GetFolderPath("MyDocuments") 

if (Test-Path -Path $folderPath)
{
    $folderPath += "\AzTS\Subscriptions\$($subId.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\"
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

if (($response | Measure-Object).Count -gt 0)
{
    $response | ConvertTo-json | out-file "$($folderpath)\ControlScanResult.json"   
    Write-Host "Check control scan result for requested subscription at[$($folderPath)]..." -ForegroundColor Green    
}

```

[Back to top…](README.md#On-this-page)

## Feedback

For any feedback contact us at: aztssup@microsoft.com 
