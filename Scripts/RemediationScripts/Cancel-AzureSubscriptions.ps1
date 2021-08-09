<##########################################

# Overivew:
    This script is used cancel all subscriptions under management group

# Pre-requesites:
    You will need owner or contributor role on management group.

# Steps performed by the script
    1. Get subscriptions under management group.

    2. Cancel subscriptions 

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to cancel subscriptions

        Cancel-AzureSubscriptions -MGName '<ManagementGroupName>' 


To know more about parameter execute:
    Get-Help Cancel-AzureSubscriptions -Detailed

########################################
#>

function Remove-AnonymousAccessOnContainers
{
    <#
    .SYNOPSIS
    This command would help in cancelling subscriptions under management group.
    .PARAMETER MGName
        Enter management group name on which remediation need to perform.
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter management group for remediation")]
        $MGName
    )

    # Get the current universal time in the default string format.
    $startTime = (Get-Date)
    $MgmtGroup = $MGName

    if ($null -eq $MgmtGroup)
    {
        throw "Missing SubsManagementGroup configuration item"
    }

    Write-Host "Preparing to query management group $MgmtGroup"
    try
    {
        $mgEntries = Get-AzManagementGroup -GroupName $MgmtGroup -Recurse -Expand
    }
    catch
    {
        Write-Error "Failed to query management group $MgmtGroup : $_"
    }
    # Limit itemList to subscriptions
    $childSubscriptions = $mgEntries.Children | Where-Object type -eq "/subscriptions"
    Write-Verbose "Successfully queried management group $MgmtGroup - found total of $($childSubscriptions.Count) subs"
    # Further limit to active subs as there may be latency between cancellation and subsequent PS executions
    $activeSubs = $childSubscriptions | % { Get-AzSubscription -SubscriptionId $_.Name | Where State -eq "Enabled" }
    Write-Verbose "Total of $($activeSubs.Count) active subscriptions"
    foreach ($sub in $activeSubs)
    {
        #Write-Host "Update-AzSubscription -SubscriptionId $($sub.SubscriptionId) -Action 'Cancel'"
        Update-AzSubscription -SubscriptionId $sub.SubscriptionId -Action "Cancel"
    }
    $endTime = Get-Date
    $totalTime = ($endTime - $startTime)
    Write-Host "Runtime: $totalTime"
}
