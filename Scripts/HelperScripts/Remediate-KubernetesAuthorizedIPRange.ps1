<###
To Remediate:
    Set-AKSClusterAuthorizedIpRange -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ResourceGroupName testRG -ResourceName testResource
###>

function Set-AKSClusterAuthorizedIpRange {
    param (
        [Parameter(Mandatory = $true)]
        [String]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [String]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [String]$ResourceName
    )

    # Ensure required modules are installed
    $requiredModules = @("Az.Accounts", "Az.Aks")
    $requiredModules | ForEach-Object {
        if (-not (Get-Module -ListAvailable -Name $_)) {
            Write-Host "Installing [$_] module..." -ForegroundColor Cyan
            Install-Module -Name $_ -Scope CurrentUser -Repository PSGallery -Force
        }
    }

    # Connect to Azure if not already connected
    $context = Get-AzContext
    if (-not $context) {
        Connect-AzAccount -Subscription $SubscriptionId | Out-Null
    }

    # Get the specific AKS cluster
    try {
        $aksCluster = Get-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $ResourceName
        
        # Check existing Authorized IP Ranges
        $existingIpRanges = $aksCluster.ApiServerAccessProfile.AuthorizedIpRanges

        if ($existingIpRanges) {
            Write-Host "Existing IP Ranges:" -ForegroundColor Yellow
            $existingIpRanges | ForEach-Object { Write-Host $_ }
            
            $choice = Read-Host "Do you want to (O)verwrite or (A)ppend IP ranges? (O/A)"
            
            if ($choice -eq 'O') {
                # Overwrite existing IP ranges
                $newIpRanges = Read-Host "Enter IP range(s) to set. For multiple ranges, separate with commas (e.g., 192.168.1.0/24,10.0.0.0/16)"
                $ipRangesToSet = $newIpRanges -split ',' | Where-Object { $_ -match '\S' }
                
                Set-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $ResourceName -ApiServerAccessAuthorizedIpRange $ipRangesToSet -Verbose:$false | Out-Null
                Write-Host "Authorized IP ranges overwritten successfully." -ForegroundColor Green
            }
            else {
                # Append to existing Authorized IP ranges
                $additionalIpRanges = Read-Host "Enter IP range(s) to add. For multiple ranges, separate with commas (e.g., 192.168.1.0/24,10.0.0.0/16)"
                $ipRangesToAdd = $additionalIpRanges -split ',' | Where-Object { $_ -match '\S' }
                
                $combinedIpRanges = $existingIpRanges + $ipRangesToAdd
                Set-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $ResourceName -ApiServerAccessAuthorizedIpRange $combinedIpRanges -Verbose:$false | Out-Null
                Write-Host "Authorized IP ranges appended successfully." -ForegroundColor Green
            }
        }
        else {
            # No existing Authorized IP ranges
            $newIpRanges = Read-Host "No existing Authorized IP ranges found. Enter IP range(s) to set. For multiple ranges, separate with commas (e.g., 192.168.1.0/24,10.0.0.0/16)"
            $ipRangesToSet = $newIpRanges -split ',' | Where-Object { $_ -match '\S' }
            
            Set-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $ResourceName -ApiServerAccessAuthorizedIpRange $ipRangesToSet -Verbose:$false | Out-Null
            Write-Host "Authorized IP ranges set successfully." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}