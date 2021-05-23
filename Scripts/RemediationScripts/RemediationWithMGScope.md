## Execute remediation script using management group

In this section, we will walk through the steps of executing remediation script using management group. 

**Note:** To execute remediation script using management group, user must have atleast reader access at MG scope (to fetch subscription list under MG scope) and Owner/Contributor/UAA role on target resources based on remediation to be applied.

Executing PowerShell scripts using management group is divided into three steps. 

> If you are new to PowerShell, then you will find several useful tips in our [PowerShell tips for new Users](https://github.com/azsk/DevOpsKit-docs/tree/master/00b-Getting-Started) guide 
> handy to accelerate your initial learning curve for PowerShell competencies needed to use AzSK effectively.

**1. Install pre-requisite Azure PS module**

``` PowerShell
# Install Az.Resources module
Install-Module Az.Resources -Scope CurrentUser -AllowClobber -Repository PSGallery
```

**2. Get subscription list under management group**

``` PowerShell
# Replace management group name
$managementGroupName = '<ManagementGroupName>'

# Array to store subscription list present under management group.
$subList= @()

function GetSubscriptionFromMG ($managementGroupName)
{
    $mgDetails = Get-AzManagementGroup -GroupName $managementGroupName -Expand -Recurse
    $mgDetails.Children | % {
    $mgDescendant =$_

    if($mgDescendant.Type -eq "/subscriptions")
    {
        $subList += $mgDescendant
    }
    elseif ($mgDescendant.Type -eq "/providers/Microsoft.Management/managementGroups")
    {
        GetSubscriptionFromMG $mgDescendant.Name
    }
    }
    return($subList)
}

$subList = GetSubscriptionFromMG $managementGroupName
```

**3. Execute remediation script with MG subscription list**

``` PowerShell
# Go to remediation section and select script. Here we will take example of deprecated account.

# Step 1: Load remediation script in current session

# Before loading remediation script in current session, please connect to AzAccount
Connect-AzAccount

# Download and load remediation script in session. Script location: https://aka.ms/azts-docs/rscript/Azure_Subscription_AuthZ_Remove_Deprecated_Accounts
. ".\Remediate-InvalidAADObjectRoleAssignments.ps1"

# Note: Make sure you copy  '.' present at the start of line.

# Step 2: Execute script using MG subscription list

# Note: Please perform discrete analysis before running remediation script using management groups.
$subList | %{
Remove-AzTSInvalidAADAccounts -SubscriptionId $_.Name -PerformPreReqCheck: $true
}

```
