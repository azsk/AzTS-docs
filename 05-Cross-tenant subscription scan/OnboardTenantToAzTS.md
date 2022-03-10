# Onboarding tenants to multi-tenant AzTS Solution

<br>

## On this page:
  - [Prerequisite](#prerequisite)
  - [Access token generation](#access-token-generation)
  - [Onboarding](#onboarding)
  - [Offboarding](#offboarding)
  - [Get Onboarded/Offboarded tenant details](#get-onboardedoffboarded-tenant-details)
  - [FAQs](#faqs)

--------------------------------------------------
<br>

## Prerequisite

Below are the prerequisites for any tenant to be onboarded to AzTS solution for security visibility:
1. SPN for the central scanning identity i.e. multi-tenant AAD application (created in step 4 of the deployment procedure) must be created in the tenant.
2. The SPN must be granted below graph permission in the tenant.

    a. MSGraphPermissions
    
        PrivilegedAccess.Read.AzureResources
        Directory.Read.All
        
    b. ADGraphPermissions
    
        Directory.Read.All
        
3. The SPN must be granted "Reader" permission on all the subscriptions in the tenant for which security visibility is required.
4. The tenant should have Azure active directory license which supports Privileged Identity Management (PIM).
5. Microsoft Defender for cloud should be enabled with standard tier for all the subscription in the tenant for which security visibility is required.

> **Note:**<br>**1.** Above mentioned prerequisites needs to be provisioned for **each tenant** that is to be onboarded to AzTS solution for security visibility.<br>**2.** Prerequisites #1 to #3 are **mandatory** for every tenant that is to be onboarded to AzTS solution. Kindly refer [these commands](MultiTenantSetupWithAADApp.md#2-onboard-tenants-for-scanning) to provision the same.<br>**3.** For prerequisite #3 its recommended to grant the SPN, "Reader" permission on root management group if security visibility is required for all the subscriptions in the tenant. This would ensure that any new subscription being added to the tenant would be automatically picked up in next scan.<br>**4.** Prerequisites #4 and #5 are **non-mandatory** but will impact certain control evaluation if not done.

[Back to top...](#on-this-page)

--------------------------------------------------
<br>

## Access token generation

Access token for invoking the onboarding/offboarding APIs can be generated using the below steps:
1. [Register an AAD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application) in the **host tenant**. This application would be used to get an access token for invoking onboarding/offboarding APIs. Skip this step if the application is already available.
> **Note:** Same AAD application can be used to onboard/offboard more tenants to the AzTS solution in future. Avoid creating multiple AAD applications for onboarding/offboarding tenants.
2. [Create secret for above application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-credentials) and store it at secure location for later reference. Skip this step if the secret is already available.
> **Note:** Above two steps involving creation of AAD application and its secret, could also be completed using `Create-AzSKTenantSecuritySolutionMultiTenantScannerIdentity` command available as a part of deployment script in a powershell session as described below.
``` PowerShell
# Clear existing login, if any

Disconnect-AzAccount
Disconnect-AzureAD

# Connect to AzureAD and AzAccount of the *host tenant*
# Host Tenant Id (Tenant in which AzTS solution needs to be installed) *must* be specified when connecting to Azure AD and AzAccount

$TenantId = "<TenantId>"
Connect-AzAccount -Tenant $TenantId
Connect-AzureAD -TenantId $TenantId

# -----------------------------------------------------------------#
# Step 1: Create AAD application and its secret
# -----------------------------------------------------------------#

# Here <AADAppDisplayName> is the display name for the AAD application to be created
# Its recommended to provide multiple owners of the AAD application for its maintenance in case any owner leave the org.

$appDetails = Create-AzSKTenantSecuritySolutionMultiTenantScannerIdentity `
                                                -DisplayName <AADAppDisplayName> `
                                                -AdditionalOwnerUPNs @('User1@Contoso.com', 'User2@Contoso.com')



# Application id of the AAD App created. This will be used in step #3 below.
$appDetails.ApplicationId

#Secret of the AAD App. This will be used in step #3 below.
#DON'T PRINT VALUE IN CONSOLE, Just use variable as is in next step
#$appDetails.Secret

```
3. Generate the access token using the below commands in a powershell session.
``` PowerShell
# Install the MSAL module. Skip if already installed
# MSAL module with version "4.35.1.3" is recommended
Install-Module -Name MSAL.PS -AllowClobber -Scope CurrentUser -repository PSGallery

$ClientSecret = '<client-secret>' | ConvertTo-SecureString -AsPlainText -Force

# Here <tenant-id> is the host tenant id for AzTS solution.
# <client-id> is the application id of the AAD application created above.
# <client-secret> is the secret of the AAD application created above.
# <webapi-scope> is api://<application id of AzTS Web API ADD application>. This was created in step #5 of the AzTS deployment.
# if the application id for AzTS Web API ADD application is "ab2xxxxx-xxxx-xxxx-xxxx-xxxxxxf18688" then <webapi-scope> would be api://ab2xxxxx-xxxx-xxxx-xxxx-xxxxxxf18688
# Kindly refer FAQ #1 in the FAQs section at bottom of this page for knowing how to get application id of AzTS Web API ADD application if you dont have it handy.
$token = Get-MsalToken -TenantId '<tenant-id>' -ClientId '<client-id>' -ClientSecret $ClientSecret -Scopes "<webapi-scope>/.default"

# Copy the access token to the clipboard for use
$token.AccessToken | Set-Clipboard

```


[Back to top...](#on-this-page)

--------------------------------------------------
<br>

## Onboarding

Tenants could be onboarded to the multi-tenant AzTS solution using the onboarding API, details for which are mentioned below.

**Request URL**

> **Note:** Kindly refer FAQ #2 in the FAQs section at bottom of this page for knowing how to get `<AzTS WebAPI-URL>`
``` PowerShell
POST <AzTS WebAPI-URL>/multitenantaction/onboardoffboardtenants?api-version=1.0
```
<br/>

**URI Parameters**
|Name|In|Type|Description|Required?|
|----|----|----|----|----|
| api-version | query | string | Version of the API to use. | No |

**Request Header**

|Param Name|Description|Required?|
|----|----|----|
| Authorization| Bearer token which can be generated by following steps [here](#access-token-generation). | Yes|

**Request Body**
|Name|Type|Description|Required?|
|----|----|----|----|
| Tenants |List<[TenantDetails](#tenantdetails)>| List of [TenantDetails](#tenantdetails) object representing Tenants to be onboarded to AzTS. | Yes |
  

#### TenantDetails

|Name|Type|Description|Required?|
|----|----|----|----|
| TenantId |string| Tenant Id. | Yes |
| TenantName| string|Tenant Name.| Yes |
| Category | string| Category of the Tenants (Learning/Demo/Support/POC).| Yes |
| TenantStatus |string| "Enabled" in case of Onboarding. | Yes |
| ManagementGroupId | string|Root Management Group Id (Same as Tenant Id).| Yes |
| AADLicense | string| Azure Active Directory license of the Tenant.| Yes |

<br/>

## **Example** 
<br/>

**Sample Request**

``` 
 POST https://azsk-azts-webapi-xxxxx.azurewebsites.net/multitenantaction/onboardoffboardtenants?api-version=1.0
```
<br/> 

**Sample Request Body**

```JSON
{
    "Tenants": [
        {
            "TenantId": "e60xxxxx-xxxx-xxxx-xxxx-xxxxxxxx7830",
            "TenantName": "mpxxxxxxxxxxxxxx",
            "Category": "Learning",
            "TenantStatus": "Enabled",
            "ManagementGroupId": "CoxxxxxxxxxxxMG",
            "AADLicense": "Azure AD Free"
        },
        {
            "TenantId": "e72xxxxx-xxxx-xxxx-xxxx-xxxxxxxx8688",
            "TenantName": "Dexxxxxxxxxxxxxx",
            "Category": "Learning",
            "TenantStatus": "Enabled",
            "ManagementGroupId": "DexxxxxxxMG",
            "AADLicense": "Azure AD Free"
        }
    ]
}
```

**Sample Response**

``` JSON
200 OK
```

[Back to top...](#on-this-page)

--------------------------------------------------
<br>

## Offboarding

Tenants could be offboarded from the multi-tenant AzTS solution using the offboarding API, details for which are mentioned below.

**Request URL**

> **Note:** Kindly refer FAQ #2 in the FAQs section at bottom of this page for knowing how to get `<AzTS WebAPI-URL>`
``` PowerShell
POST <AzTS WebAPI-URL>/multitenantaction/onboardoffboardtenants?api-version=1.0
```
<br/>

**URI Parameters**
|Name|In|Type|Description|Required?|
|----|----|----|----|----|
| api-version | query | string | Version of the API to use. | No |

**Request Header**

|Param Name|Description|Required?|
|----|----|----|
| Authorization| Bearer token which can be generated by following steps [here](#access-token-generation). | Yes|

**Request Body**
|Name|Type|Description|Required?|
|----|----|----|----|
| Tenants |List<[TenantDetails](#tenantdetails-1)>| List of [TenantDetails](#tenantdetails-1) object representing Tenants to be offboarded from AzTS. | Yes |
  
#### TenantDetails
|Name|Type|Description|Required?|
|----|----|----|----|
| TenantId |string| Tenant Id. | Yes |
| TenantStatus |string| "Disabled" in case of Offboarding. | Yes |

<br/>

## **Example** 
<br/>

**Sample Request**

``` 
 POST https://azsk-azts-webapi-xxxxx.azurewebsites.net/multitenantaction/onboardoffboardtenants?api-version=1.0
```
<br/> 

**Sample Request Body**

```JSON
{
    "Tenants": [
        {
            "TenantId": "e60xxxxx-xxxx-xxxx-xxxx-xxxxxxxx7830",
            "TenantStatus": "Disabled"
        },
        {
            "TenantId": "e72xxxxx-xxxx-xxxx-xxxx-xxxxxxxx8688",
            "TenantStatus": "Disabled"
        }
    ]
}
```

**Sample Response**

``` JSON
200 OK
```

[Back to top...](#on-this-page)

--------------------------------------------------
<br>

## Get Onboarded/Offboarded tenant details

Get the details of all the onboarded/offboarded tenants using the API, details for which are mentioned below.

**Request URL**

> **Note:** Kindly refer FAQ #2 in the FAQs section at bottom of this page for knowing how to get `<AzTS WebAPI-URL>`
``` PowerShell
POST <AzTS WebAPI-URL>/multitenantaction/gettenantdetails?api-version=1.0
```
<br/>

**URI Parameters**
|Name|In|Type|Description|Required?|
|----|----|----|----|----|
| api-version | query | string | Version of the API to use. | No |

**Request Header**

|Param Name|Description|Required?|
|----|----|----|
| Authorization| Bearer token which can be generated by following steps [here](#access-token-generation). | Yes|

**Request Body**
|Name|Type|Description|Required?|
|----|----|----|----|
| Tenants |List<[TenantDetails](#tenantdetails-2)>| List of [TenantDetails](#tenantdetails-2) object representing tenants for which details is to be fetched from AzTS. | No |
  
#### TenantDetails
|Name|Type|Description|Required?|
|----|----|----|----|
| TenantId |string| Tenant Id. | No |

<br/>

## **Example** 
<br/>

**Sample Request**

``` 
 POST https://azsk-azts-webapi-xxxxx.azurewebsites.net/multitenantaction/gettenantdetails?api-version=1.0
```
<br/> 

**Sample Request Body**

```JSON
{
    "Tenants": [
        {
            "TenantId": "e60xxxxx-xxxx-xxxx-xxxx-xxxxxxxx7830"
        },
        {
            "TenantId": "e72xxxxx-xxxx-xxxx-xxxx-xxxxxxxx8688"
        }
    ]
}
```

**Sample Response**

``` JSON
{
    "tenants": [
        {
            "tenantId": "e60xxxxx-xxxx-xxxx-xxxx-xxxxxxxx7830",
            "tenantName": "mpxxxxxxxxxxxxxx",
            "category": "Learning",
            "tenantStatus": "Enabled",
            "managementGroupId": "CoxxxxxxxxxxxMG",
            "mgHierarchyTraverseLimit": 7,
            "onboardedOn": "2022-02-23 06:37:19",
            "offboardedOn": null,
            "aadLicense": "Azure AD Free"
        },
        {
            "tenantId": "e72xxxxx-xxxx-xxxx-xxxx-xxxxxxxx8688",
            "tenantName": "Dexxxxxxxxxxxxx",
            "category": "Learning",
            "tenantStatus": "Enabled",
            "managementGroupId": "DexxxxxxxxMG",
            "mgHierarchyTraverseLimit": 7,
            "onboardedOn": "2022-02-23 06:39:31",
            "offboardedOn": null,
            "aadLicense": "Azure AD Free"
        }
    ]
}
```

**Sample Request Body to fetch details for all the tenants**

```JSON
{}
```

**Sample Response**

``` JSON
{
    "tenants": [
        {
            "tenantId": "e60xxxxx-xxxx-xxxx-xxxx-xxxxxxxx7830",
            "tenantName": "mpxxxxxxxxxxxxxx",
            "category": "Learning",
            "tenantStatus": "Enabled",
            "managementGroupId": "CoxxxxxxxxxxxMG",
            "mgHierarchyTraverseLimit": 7,
            "onboardedOn": "2022-02-23 06:37:19",
            "offboardedOn": null,
            "aadLicense": "Azure AD Free"
        },
        {
            "tenantId": "e72xxxxx-xxxx-xxxx-xxxx-xxxxxxxx8688",
            "tenantName": "Dexxxxxxxxxxxxx",
            "category": "Learning",
            "tenantStatus": "Enabled",
            "managementGroupId": "DexxxxxxxxMG",
            "mgHierarchyTraverseLimit": 7,
            "onboardedOn": "2022-02-23 06:39:31",
            "offboardedOn": null,
            "aadLicense": "Azure AD Free"
        },
        {
            "tenantId": "b59xxxxx-xxxx-xxxx-xxxx-xxxxxxxx4c6d",
            "tenantName": "Coxxxxx",
            "category": "Learning",
            "tenantStatus": "Enabled",
            "managementGroupId": "b5xxxxxx-xxxx-xxxx-xxxx-xxxxxxxx4c6d",
            "mgHierarchyTraverseLimit": 7,
            "onboardedOn": "2022-02-28 15:34:40",
            "offboardedOn": null,
            "aadLicense": "Azure AD Premium P2"
        }
    ]
}
```

[Back to top...](#on-this-page)

--------------------------------------------------
<br>

## FAQs

**1. How to get application id for the AzTS Web API ADD application?**

1. Go to Azure Portal.
2. Go to **Resource Groups**.
3. Select your Resource Group where you have done AzTS setup.
4. Select the App Service for API '**AzSK-AzTS-WebAPI-xxxxx**'.
5. In the app's left menu, select **Configuration > Application settings**.
6. Search the app setting **AADClientAppDetails__ApplicationId**. This is application id for the AzTS Web API ADD application.

**2. How to get the AzTS Web API URL?**

1. Go to Azure Portal.
2. Go to **Resource Groups**.
3. Select your Resource Group where you have configured AzTS setup.
4. Select the App Service for API '**AzSK-AzTS-WebAPI-xxxxx**'.
5. In Overview section, copy URL.

[Back to top...](#on-this-page)
