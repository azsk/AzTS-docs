# Onboarding tenants to multi-tenant AzTS Solution

<br>

## On this page:
  - [Prerequisite](#prerequisite)

--------------------------------------------------
<br>

## Prerequisite

Below are the prerequisites for any tenant to be onboarded to AzTS solution for security visibility:
1. SPN for the central scanning identity i.e. multi-tenant AAD application, which was created in step 4 of the deployment procedure, must be created in the tenant.
2. The SPN must be granted below graph permission in the tenant.

    a. MSGraphPermissions
    
        PrivilegedAccess.Read.AzureResources
        Directory.Read.All
        
    b. ADGraphPermissions
    
        Directory.Read.All
        
3. The SPN must be granted "Reader" permission to all the subscriptions in the tenant.
4. The tenant should have Azure active directory license which supports Privileged Identity Management (PIM).
5. Microsoft Defender for cloud should be enabled with standard tier for all the subscription in the tenant.

> **Note:**<br>**1.** Above mentioned prerequisites needs to be provisioned for **each tenant** that is to be onboarded to AzTS solution for security visibility.<br>**2.** Prerequisites #1 to #3 are mandatory for every tenant that is to be onboarded to AzTS solution. Kindly refer these commands to provision the same.<br>**3.** For prerequisite #3 its recommended to grant the SPN, "Reader" permission on root management group. This would ensure that any new subscription added to the tenant would be automatically picked up in next scan.<br>**4.** Prerequisites #4 and #5 are non-mandatory but will impact control evaluation if not done.
