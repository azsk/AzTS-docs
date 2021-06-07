$fn = "<ManagementGroupName>"
# Input bindings are passed in via param block.
param($Timer)


function CancelMGSubscription($fn)
{
    
    # The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
    if ($Timer.IsPastDue)
    {
        Write-Host "$fn timer is running late!"
    }
    else
    {
        Write-Host "$fn starting at $(Get-Date)"
    }

    # Get the current universal time in the default string format.
    $startTime = (Get-Date)
    $MgmtGroup = $env:SubsManagementGroup

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
    # Write an information log with the current time.
    Write-Host "$fn completed processing at $endTime"
    Write-Host "Runtime: $totalTime"
}

# Method to cancel active subscriptions present in provided management group
CancelMGSubscription $fn