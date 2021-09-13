----------------------------------------------

> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..
# On Demand Scan using API 

### On this page:
- [Overview](README.md#overview)
- [Create client app registration](README.md#Register-an-application-in-Azure-AD-to-represent-a-client-application)
- [Generate user authentication token to access subscriptions](README.md#Generate-user-authentication-token-to-access-subscriptions)
- [API to scan a subscription](README.md#API-to-scan-a-subscription)
- [API to get control scan result](README.md#API-to-get-control-scan-result)
- [Feedback](README.md#Feedback)

-----------------------------------------------------------------
## Overview 
The Azure Tenant Security Solution (AzTS) provides APIs to allow on demand scan for a subscription and get control scan result.

## Register an application in Azure AD to represent a client application
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

> **Note for WebAPI Admin**
> </br>
> _Enable the flag 'OnDemandScanAPI' in order to provide access over API endpoints._

[Back to top…](README.md#On-this-page)

## Generate user authentication token to access subscriptions
User has to generate authentication token in order to use APIs for any subscription.
There are two ways to generate access tokens:
- Using client credential flow
- Using user authentication code flow

#### Required Az Module
``` PowerShell
Install-Module -Name MSAL.PS -AllowClobber -Scope CurrentUser -repository PSGallery
```

### Using client credential flow
Client crediential flow uses the client credentials (client id and client secret) to generate the token. Token will be generated against specified SPN (Service Principal Name) and **SPN must have access over the subscription** to scan or to get the control scan result.

> **Note:** You need to run RBAC after granting the permission to SPN over subscription.
> </br>
> In order to generate the token for APIs, you have to get access for the client application from WebAPI owner.
> 1. Send the client id to WebAPI owner to request access for client application.
> 2. WebAPI owner will grant the access and share the scope.
> 3. Use WebAPI scope in below command.
> </br>
</br>

**Steps for WebAPI owner to get scope:**
> 1. Go to Azure Portal.
> </br>
> 2. Go to App Registration.
> </br>
> 3. Select WebAPI App Registration.
> </br>
> 4. Go to 'Expose an API'.
> </br>
> 5. Copy scope from 'Scopes'.
> </br>

Commands to generate the token:
``` PowerShell

$ClientSecret = '<client-secret>' | ConvertTo-SecureString -AsPlainText -Force

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-id>' -ClientSecret $ClientSecret -Scopes "<WebAPI-scope>/.default"

$header = "Bearer " + $token.AccessToken

$headers = @{"Authorization"=$header;"Content-Type"="application/json";}

```

[Back to top…](README.md#On-this-page)

### Using user authentication code flow
User authentication code flow uses user's crediential to generate the token. User must have access over the subscription  to scan or to get the control scan result.

> **Note for WebAPI Admin**
> </br>
> WebAPI must have 'Admin consent' granted to expose the APIs.
> </br>
> Grant admin consent for client app registration:
> 1. Go to Azure Portal.
> 2. Go to 'App Registration'.
> 3. Select appropriate 'App Registration'.
> 4. Go to 'API Permissions'.
> 5. Click 'Grant admin consent for Microsoft'.


Command to generate the token:
``` PowerShell

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-app-id>' -RedirectUri 'https://localhost' -Scopes '<WebAPI-scope>'

$header = "Bearer " + $token.AccessToken

$headers = @{"Authorization"=$header;"Content-Type"="application/json";}

```

[Back to top…](README.md#On-this-page)

## API to scan a subscription

``` PowerShell
POST https://AzSK-AzTS-WebApi-xxxxx.azurewebsites.net/adhocscan/RequestScan
```

Provide request body parameter like below:
``` PowerShell
$requestBody = @{"SubscriptionIDList"=@("{subscriptionId1}","{subscriptionId2}",...);}
```

``` PowerShell

$apiResponse = Invoke-WebRequest -Method 'POST' -Uri $apiUri -Headers $headers -Body ($requestBody | ConvertTo-Json) -UseBasicParsing

$response = ConvertFrom-Json $apiResponse.Content
$response
```

The following shows an example of the output:
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
> </br>

**Request body parameter details:**
|Param Name|Description|Required?
|----|----|----|
| SubscriptionId| List of subscription id(s) for scan. | Yes|

</br>

[Back to top…](README.md#On-this-page)

## API to get control scan result

``` PowerShell
POST https://AzSK-AzTS-WebApi-xxxxx.azurewebsites.net/adhocscan/subscription/{subscriptionId}/ControlScanResult
```

Within the URI, replace {subscriptionId} with the Subscription Id for which you want to get control scan result.

</br>

Provide request body parameter like below:
``` PowerShell
$requestBody = @{}
# Example:
$requestBody = @{"scanRequestId"="{scanRequestId}";"ControlIdList"=@("control_id1","control_id1");"ResourceNameList"=@("resource1","resource2");}
```

> Note:
> </br>
> _If 'requestBody' is empty then API will return latest control scan result._

**Request body parameter details:**
|Param Name|Description|Required?
|----|----|----|
| ScanRequestId | To get control scan result with respect to the scan request id. | Yes |
| ControlIdList| List of control ids to get control result only for specific controls.| No |
| ResourceNameList | List of resources to get control result only for certain resources.| No |

``` PowerShell

$apiResponse = Invoke-WebRequest -Method $method -Uri $apiUri -Headers $headers -Body ($requestBody | ConvertTo-Json) -UseBasicParsing

$response = ConvertFrom-Json $apiResponse.Content

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
> **Note:** 
> </br>
> You can get entire control scan result only for one subscription at a time.

</br>

[Back to top…](README.md#On-this-page)

## Feedback

For any feedback contact us at: aztssup@microsoft.com 
