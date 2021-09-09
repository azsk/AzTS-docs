----------------------------------------------

> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..
# On Demand Scan using API 

### On this page:
- [Overview](OnDemandScanAPIs.md#overview)
- [Create client app registration](OnDemandScanAPIs.md#Create-client-app-registration)
- [Generate user authentication token to access subscriptions](OnDemandScanAPIs.md#Generate-user-authentication-token-to-access-subscriptions)
- [API to scan a subscription](OnDemandScanAPIs.md#API-to-scan-a-subscription)
- [API to get control scan result](OnDemandScanAPIs.md#API-to-get-control-scan-result)
- [Feedback](OnDemandScanAPIs.md#Feedback)

-----------------------------------------------------------------
## Overview 
The Azure Tenant Security Solution (AzTS) exposes APIs for users to allow on demand scan for a subscription and get control scan result using APIs.

## Create client app registration
Before generating the token or making an API call, client app registration needs to be created.
</br>
Follow below steps to create client application:
1. Go to the Azure portal to register your application.

2. Search for and select App registrations.

3. Select New registration.

4. When the Register an application page appears, enter your application's registration information:

    - In the Name section, enter a meaningful application name that will be displayed to users of the app, such as client-app.

    - In the Supported account types section, select Accounts in any organizational directory (Any Azure AD directory - Multitenant).

5. In the Redirect URI section, select Web and leave the URL field empty for now.

6. Select Register to create the application.

7. On the app Overview page, find the Application (client) ID value and record it for later.

8. Create a client secret for this application to use in a subsequent step.

    - From the list of pages for your client app, select Certificates & secrets, and select New client secret.

    - Under Add a client secret, provide a Description. Choose when the key should expire, and select Add.

9. When the secret is created, note the key value for use in a subsequent step

</br>


[Back to top…](OnDemandScanAPIs.md#On-this-page)

## Generate user authentication token to access subscriptions
User has to generate authentication token in order to get access over a subscription.
There are two ways to generate access tokens:
- Using client credential flow
- Using user authentication code flow

### Using client credential flow
Client crediential flow uses the client credentials(client id and client secret) to generate the token. Token will be generating against specified SPN and **SPN must have access over the subscription** to scan or to get the control scan result.

Steps to generate the token:
``` PowerShell

$ClientSecret = '<client-secret>' | ConvertTo-SecureString -AsPlainText -Force

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-id>' -ClientSecret $ClientSecret -Scopes "<WebAPI-scope>"

$token.AccessToken | ConvertTo-Json | Out-File '<token file path>\token.json'

```

[Back to top…](OnDemandScanAPIs.md#On-this-page)

### Using user authentication code flow
User authentication code flow uses user's crediential to generate the token. User must have access over the subscription  to scan or to get the control scan result.

> In this flow, Client app registration needs "Admin consent" to access the APIs.
> </br>
> Grant admin consent for client app registration:
> 1. Go to Azure Portal.
> 2. Go to App Registration.
> 3. Select appropriate App Registration.
> 4. Go to 'API Permissions'.
> 5. Click 'Grant admin consent for Microsoft'.


Steps to generate the token:
``` PowerShell

$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-app-id>' -RedirectUri 'https://localhost' -Scopes 'api://06b8fce5-a6a9-470a-b05d-a7557b7a704c/user_impersonation'

```

[Back to top…](OnDemandScanAPIs.md#On-this-page)

## API to scan a subscription

Use below PowerShell command to get control scan result.

``` PowerShell

$header = "Bearer " + $token.AccessToken
$headers = @{"Authorization"=$header;"Content-Type"="application/json";}
$requestBody = @{{"SubscriptionIDList"=@("subscription_id");}

# Example:
$requestBody = @{"SubscriptionIDList"=@("sub1","sub2");}


$method = [Microsoft.PowerShell.Commands.WebRequestMethod]::POST
$apiUri = "https://localhost:5001/adhocscan/RequestScan"

try
{
    $apiResponse = Invoke-WebRequest -Method $method -Uri $ascUri -Headers $headers -Body ($requestBody | ConvertTo-Json) -UseBasicParsing
}
catch
{
    Write-Host "Error occured while scanning the subscription."
}

$response = ConvertFrom-Json $apiResponse.Content

```

**Request body parameter details:**
|Param Name|Description|Required?
|----|----|----|
| SubscriptionId| List of subscription id(s) for scan. | Yes|

</br>

[Back to top…](OnDemandScanAPIs.md#On-this-page)

## API to get control scan result
Use below PowerShell command to get control scan result.

``` PowerShell

$header = "Bearer " + $token.AccessToken
$headers = @{"Authorization"=$header;"Content-Type"="application/json";}
$requestBody = @{}

# Example:
$requestBody = @{"scanRequestId"="scan_request_id";"ControlIdList"=@("control_id1","control_id1");"ResourceNameList"=@("resource1","resource2");}


$method = [Microsoft.PowerShell.Commands.WebRequestMethod]::POST
$apiUri = "https://localhost:5001/adhocscan/subscription/<sub-id>/ControlScanResult"

try
{
    $apiResponse = Invoke-WebRequest -Method $method -Uri $ascUri -Headers $headers -Body ($requestBody | ConvertTo-Json) -UseBasicParsing
}
catch
{
    Write-Host "Error occured while getting the control scan result."
}

$response = ConvertFrom-Json $apiResponse.Content

```


**Request body parameter details:**
|Param Name|Description|Required?
|----|----|----|
| ScanRequestId | To get control scan result with respect to the scan request id.| Yes |
| ControlIdList| List of control ids to get control result only for specific controls.| No |
| ResourceNameList | List of resources to get control result only for certain resources.| No |


</br>

> **Note:** 
> </br>
> _1. Enable the flag 'OnDemandScanAPI' in order to expose API endpoints._
> </br>
> _2. On demand scan for each subcription can be requested maximum 10 times in a day._
> </br>
> _3. You can get entire control result only for one subscription at a time._
> </br>
> _4. If ScanRequestId is empty then API will return latest control scan result._
> </br>

[Back to top…](OnDemandScanAPIs.md#On-this-page)

## Feedback

For any feedback contact us at: aztssup@microsoft.com 
