## Execute remediation script using management group Id to fix failed controls of Azure Tenant Security Solution - Step by Step
In this section, we will walk through the steps of executing remediation script using management group Id.

**Note:** To execute remediation script using management group, user must have Owner access on MG scope.

Executing script using management group Id is divided into three steps:

**1. Install pre-requisite module**

``` Powershell
# Install Az.Resources module
Install-Module Az.Resources -Scope CurrentUser -AllowClobber -Repository PSGallery
```

**2. Get subscription list under management group**
``` Powershell
# Replace management group id value
$managementGroupId = '<ManagementGroupId>'

$subList= @()

function GetSubscriptionFromMG ($managementGroupId)
{
    $mgDetails = Get-AzManagementGroup -GroupName $managementGroupId -Expand -Recurse
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
}

# Get subList using management group Id
GetSubscriptionFromMG $managementGroupId
```

**3. Execute remediation script with MG subscription list**

``` Powershell
# Go to remediation section and select script. Here we will take example of deprecated account.

# Step 1: Load remediation script in current session

# Before loading remediation script in current session, please connect to AzAccount
Connect-AzAccount

# Load remediation script in session
. ".\<RemediationScriptFileName>.ps1"

# Note: Make sure you copy  '.' present at the start of line.

# Step 2: Execute script using MG subscription list

# Note: Please perform descrete analysis before running remediation script using management groups.
$subList | %{
Remove-AzTSInvalidAADAccounts -SubscriptionId $_.Name -PerformPreReqCheck: $true
}

```