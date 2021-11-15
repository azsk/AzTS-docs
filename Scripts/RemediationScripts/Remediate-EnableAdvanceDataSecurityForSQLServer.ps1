<###
# Overview:
    This script is used to enable Advance Threat Protection for SQL Servers in a Subscription.

# Control ID:
    Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server

# Display Name:
    Enable advanced data security on your SQL servers

# Prerequisites:
    Contributor and higher privileges on the SQL Servers in a Subscription.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription that do not have Advance Threat Protection enabled.
        3. Back up details of SQL Server that are going to be remediated.
        4. Enable Advance Threat Protection on the SQL Server in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable Advance Threat Protection on the SQL Server in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable Advance Threat Protection on the SQL Server in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable Advance Threat Protection on the SQL Server in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Server  details in a Subscription that will be remediated:
    
           Enable-ThreatDetectionForSQLServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To enable Advance Threat Protection on the SQL Server in a Subscription:
       
           Enable-ThreatDetectionForSQLServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000

        3. To enable Advance Threat Protection on the SQL Server  in a Subscription, from a previously taken snapshot:
       
           Enable-ThreatDetectionForSQLServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServerDatabases\SQLServerDatabasesWithTDEDisabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-ThreatDetectionForSQLServers -Detailed

    To roll back:
        1. To disable Advance Threat Protection on theSQL Server  in a Subscription, from a previously taken snapshot:

           Disable-ThreatDetectionForSQLServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServerDatabases\RemediatedSQLServerDatabases.csv
        
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-ThreatDetectionForSQLServers -Detailed        
###>

function Setup-Prerequisites
{
    <#
        .SYNOPSIS
        Checks if the prerequisites are met, else, sets them up.

        .DESCRIPTION
        Checks if the prerequisites are met, else, sets them up.
        Includes installing any required Azure modules.

        .INPUTS
        None. You cannot pipe objects to Setup-Prerequisites.

        .OUTPUTS
        None. Setup-Prerequisites does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Setup-Prerequisites

        .LINK
        None
    #>

    # List of required modules
    $requiredModules = @("Az.Accounts", "Az.Sql")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}

function Enable-ThreatDetectionForSQLServers
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server' Control.

        .DESCRIPTION
        Remediates 'Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server' Control.
        Advance Threat Protection must be enabled. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .EXAMPLE
        PS> Enable-ThreatDetectionForSQLServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-ThreatDetectionForSQLServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-ThreatDetectionForSQLServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableThreatDetectionForSQLServers\SQLServersWithThreatDetectionDisabled.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to enable Advance Threat Protection for SQL Server(s) in Subscription: $($SubscriptionId)"
    Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if $($context.Account.Id) is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "*** To enable Advance Threat Protection for SQL Server(s) in a Subscription, Contributor and higher privileges on the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
   
    # Safe Check: Current user must have Owner/Contributor/User Access Administrator access over the subscription.
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    $requiredRoleDefinitionName = @("Owner", "Contributor", "User Access Administrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName} | Measure-Object).Count -le 0 )
    {
        Write-Host "Warning: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]." -ForegroundColor Yellow
        #return;
    }
    else
    {
        Write-Host "Current user [$($currentSub.Account.Id)] has the required permission for subscription [$($SubscriptionId)]." -ForegroundColor Green
    }
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all SQL Servers..."

    $sqlServersResources = @()

    # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all SQL Servers in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all SQL Servers in a Subscription      
        $sqlServersResources = Get-AzSqlServer -ErrorAction Stop
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all SQL Servers from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
        
        #Importing the file
        $sqlServersDetails = Import-Csv -LiteralPath $FilePath

        $validSqlServersDetails = $sqlServersDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        $sqlServerResources = @()
        $validSqlServersDetails | ForEach-Object {
            $resourceId = $_.ResourceId

            try
            {
                $sqlServerResource = Get-AzSqlServer -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                $sqlServerResources += $sqlServerResource
            }
            catch
            {
                Write-Host "Error fetching SQL Server resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this SQL Server resource..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }

    $totalSQLServers = $sqlServerResources.Count

    if ($totalSQLServers -eq 0)
    {
        Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
    
    Write-Host "Found $($totalSQLServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Fetching SQL Servers ..."

    # Includes SQL Servers where Advance Threat Protection is enabled.
    $sqlServersWithThreatDetectionEnabled  = @()

    # Includes SQL Servers where Advance Threat Protection is not enabled.
    $sqlServersWithThreatDetectionDisabled  = @()

    $sqlServerResources | ForEach-Object{
        
        try
        {
            Write-Host "Fetching SQL Server resource: Resource ID - $($_.ResourceId)"
            #Details related to SQL Server.   
            $sqlServerAuditDetails = Get-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName 
            $sqlServerDetails = Get-AzSqlServerAdvancedThreatProtectionSetting -ServerName $_.ServerName -ResourceGroupName $_.ResourceGroupName 
            if($sqlServerAuditDetails.BlobStorageTargetState -eq "Enabled" -or $sqlServerAuditDetails.EventHubTargetState -eq "Enabled" -or $sqlServerAuditDetails.LogAnalyticsTargetState -eq "Enabled")
            {
                $sqlServerAuditStatus = $true
            }
            else
            {
                $sqlServerAuditStatus = $false   
            }

            $isAlertPoliciesEnabled = $sqlServerDetails.ThreatDetectionState   
            $isAlertPoliciesEnabled = $isAlertPoliciesEnabled -eq "Enabled" 
            $noDisabledAlerts = $sqlServerDetails.ExcludedDetectionTypes.Count 
            $noDisabledAlerts = $noDisabledAlerts -eq 0 
            $listofDisabledAlerts = $sqlServerDetails.ExcludedDetectionTypes
            $listofDisabledAlerts = $listofDisabledAlerts -join ","
            $isEmailAccountAdminsConfigured = $sqlServerDetails.EmailAdmins
            $hasEmailAddresses = $sqlServerDetails.NotificationRecipientsEmails.Length
            $listOfEmailAddress = $sqlServerDetails.NotificationRecipientsEmails
            $listOfEmailAddress = $listOfEmailAddress -join ","
            $hasEmailAddresses = $hasEmailAddresses -gt 0

            if(-not($isEmailAccountAdminsConfigured -or $hasEmailAddresses))
            {
                #Fetching details related to Advance Threat Protection at Subscription level.
                $ascContactDetails = Get-AzSecurityContact 
                if( $ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].Email).Length -ne 0 )
                {
                    $hasEmailAddresses = $true
                    $ascContactDetails | ForEach-Object {
                        $listOfEmailAddress += $_.Email
                    }
                    $listOfEmailAddress = $listOfEmailAddress -join ","
                }

                if( $ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].AlertsToAdmins -eq "on"))
                {
                    $isEmailAccountAdminsConfigured = $true   
                }
            }

            #checking if the server is having Advance threat protection enabled.
            if ($sqlServerAuditStatus -and $isAlertPoliciesEnabled -and $noDisabledAlerts -and ($isEmailAccountAdminsConfigured -or $hasEmailAddresses ))
            {
                $sqlServersWithThreatDetectionEnabled  += $_ 
            }
            else
            {
                $sqlServersWithThreatDetectionDisabled  += $_ |Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ServerName';E={$_.ServerName}},
                                                                        @{N='SqlServerAuditStatus';E={$sqlServerAuditStatus}},
                                                                        @{N='IsAlertPoliciesEnabled';E={$isAlertPoliciesEnabled}},
                                                                        @{N='NoDisabledAlerts';E={$noDisabledAlerts}},
                                                                        @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                        @{N='HasEmailAddresses';E={$hasEmailAddresses}},
                                                                        @{N="ListOfEmailAddresses"; E = {$listOfEmailAddress}},
                                                                        @{N='ListOfDisabledAlerts'; E={$listofDisabledAlerts}}
            }       
        }
        catch
        {
            $sqlServersWithThreatDetectionDisabled  += $_ |Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ServerName';E={$_.ServerName}},
                                                                        @{N='SqlServerAuditStatus';E={$sqlServerAuditStatus}},
                                                                        @{N='IsAlertPoliciesEnabled';E={$isAlertPoliciesEnabled}},
                                                                        @{N='NoDisabledAlerts';E={$noDisabledAlerts}},
                                                                        @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                        @{N='HasEmailAddresses';E={$hasEmailAddresses}},
                                                                        @{N="ListOfEmailAddresses"; E = {$listOfEmailAddress}},
                                                                        @{N='ListOfDisabledAlerts'; E={$listofDisabledAlerts}}
            Write-Host "Error fetching advance threat protection configuration: Resource ID - $($_.ResourceId), Resource Group Name - $($_.ResourceGroupName), Resource Name - $($_.ServerName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }
  
    $totalSQLServersWithThreatDetectionDisabled = ($sqlServersWithThreatDetectionDisabled | Measure-Object).Count
    if ($totalSQLServersWithThreatDetectionDisabled -eq 0)
    {
        Write-Host "No SQL Server found with Advance Threat Protection disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSQLServersWithThreatDetectionDisabled) SQL Server (s) with Advance Threat Protection disabled." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableThreadDetectionForSQLServers"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up SQL Server details to $($backupFolderPath)\SQLServersWithThreatDetectionDisabled.csv"
    
    # Backing up SQL Server  details.
    $backupFile = "$($backupFolderPath)\SQLServersWithThreatDetectionDisabled.csv"
    $sqlServersWithThreatDetectionDisabled  | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {   
        if (-not $Force)
        {
            Write-Host "Do you want to enable Advance Threat Protection for all SQL Servers ? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "occurred will not be enabled for SQL Server . Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Advance Threat Protection will be enabled forSQL Server ." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enabling Advance Threat Protection for SQL Server ..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $remediatedSQLServers = @()
        
        # Includes SQL Servers that were skipped during remediation. There were errors remediating them.
        $skippedSQLServers = @()

        write-Host "do you want to remediate at Subscription level or server level"
        $level = Read-Host -Prompt "(Subscription-1|server-2)"

        Write-Host "we are currently supporting storage account only for storing the audit logs of SQL sever." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Do you want to create a centralized Storage Account or seperate Storage Account for each SQL Server to store the auditing logs".
        
        $storageAccountType = Read-Host -Prompt "(centralized-1|seperate-2)"

        #delete this
        $storageAccountCentralized = Get-AzStorageAccount -ResourceGroupName v-prsomaniTestRG -Name "stracc11111"

        if($storageAccountType -eq "1")
        {
            Write-Host "Do you want to use a exisiting storage account or do you want to create a new one  for storing the auditing logs?"
            $type = Read-Host -Prompt ("Exisiting-1|New-2")
            try
            {

            
                if($type -eq "1")
                {
                    Write-Host "please provide the resource group name"
                    $resourceGroupName = Read-Host -Prompt "(Resource Group Name)"
                    Write-Host " Please provide the storage account name"
                    $storageAccountName = Read-Host -Prompt "(Storage Account Name)"
                    Write-Host " Fetching storage account.."
                    $storageAccountCentralized = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName
                }
                else
                {
                    # Write-Host "Please provide the resource group name for centralized storage account"
                    #$resourceGroupName = Read-Host -Prompt "(Resource Group name)"
                    #$storageAccountName = "storageaccountsqlauditinglogs"+(Get-Random -Maximum 99999 -Minimum 1000)
                    #Write-Host " Creating Centralized storage account.."
                    #$storageAccountCentralized = New-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName -SkuName Standard_LRS -Location "East US"
                    Write-Host "successfully created Centralized storage Account with Resource Id : $($storageAccountCentralized.ResourceId)"
                }
            }
            catch
            {
                Write-Host "Error: $($_)"
                Write-Host "Exiting..."
                #break
            }
           
        }

        #if remediation is at Subscription level this block is going to execute
        if($level -eq "1")
        {   
            try
            {
                $sqlServerPricingDetails = Get-AzSecurityPricing -Name "SqlServers" 
                if(($sqlServerPricingDetails | measure-Object).Count -eq 0)
                {
                    Write-Host "Advance Threat Protection is already enabled at the subscription level." -ForegroundColor $([Constants]::MessageType.Update)
                }
                else
                {
                    Write-Host "Remediating at server level will cost you 15$ per Server per month"
                    Write-Host "Enabling Advance threat protection on Subscription $($SubscriptionId)"
                    Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard"
                    Write-Host "successfully enabled Advance threat protection on the Subscription $($SubscriptionId)"
                }

                $ascContactDetails = Get-AzSecurityContact
                if($ascContactDetails.Count -gt 0 -and (($ascContactDetails[0].Email).Length -eq 0 -or ($ascContactDetails[0].AlertsToAdmins) -eq "on"))
                {
                    Write-Host "Contact details on the Subscription $($SubscriptionId) is already configured"  
                }
                else
                {
                    Write-Host "setting contact details on the Subscription $($SubscriptionId)"
                    Set-AzSecurityContact -Name $context.Account.Id  -Email $context.Account.Id -AlertAdmin -NotifyOnAlert
                    Write-Host "contact details has been set successfully on the Subscription $($SubscriptionId)"
                }
           
                $ascContactDetails = Get-AzSecurityContact    
            }
            catch
            {
                Write-Host "Error while remediating at Subscription level. Error $($_)"
                Write-Host "Exiting..."
                break
            }

            #Checking email addresses is configured at the Subscription.
            if($ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].Email).Length -ne 0 )
            {
                $hasEmailAddressesAtServer = $true
            }
            else
            {   
                $hasEmailAddressesAtServer = $false
            }
            
            #Checking email account admin configured.
            if( $ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].AlertsToAdmins -eq "on"))
            {
                $isEmailAccountAdminsConfiguredAtserver = $true   
            }
            else
            {
                $isEmailAccountAdminsConfiguredAtserver = $false
            }

            Write-Host "checking advance threat Protection at server level". -ForegroundColor $([Constants]::MessageType.Info)
            
            #Checking at the server level.
            $countOfStorageAccount = 111
            $sqlServersWithThreatDetectionDisabled  | ForEach-Object{
                
                Write-Host "Fetching SQL Server Resource Id: $($_.ResourceId) for remediation"

                try
                {
                    if($_.ResourceGroupName) # add the condition that the server is normal not the synapse
                    {
                        if($_.SqlServerAuditStatus -eq $false)
                        {   
                            
                            if($storageAccountType -eq "2")
                            {  
                                #creating storage account for every server
                                $storageAccountName = "storageaccountsqlauditinglogs"+ $countOfStorageAccount
                                $countOfStorageAccount += 1
                                $storageAccountSeperated = New-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $storageAccountName -SkuName Standard_LRS -Location "East US" 
                                if(($storageAccountSeperated|Measure-Object).count -ne 0)
                                {
                                    Write-Host "Storage account $($storageAccountSeperated.Id) is successfully created for SQL Server $($_.ServerName) "
                                }

                                Set-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountSeperated.Id 
                            }
                            else
                            {
                                Set-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountCentralized.Id  
                            }

                            $sqlServerAuditDetails = Get-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                            
                            if($sqlServerAuditDetails.BlobStorageTargetState -eq "Enabled" -or $sqlServerAuditDetails.EventHubTargetState -eq "Enabled" -or $sqlServerAuditDetails.LogAnalyticsTargetState -eq "Enabled")
                            {
                                $sqlServerAuditStatus = $true
                            }
                            else
                            {
                                $sqlServerAuditStatus = $false   
                            }
                        }

                        if($hasEmailAddressesAtServer)
                        {
                            $_.IsEmailAccountAdminsConfigured = $isEmailAccountAdminsConfiguredAtserver
                            $_.HasEmailAddresses = $true
                            Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType "" 
                        }
                        else
                        {
                            if($_.HasEmailAddresses -eq $true)
                            {
                                Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType ""   
                            }
                            else
                            {
                                $userEmailAddresss = $context.Account.Id
                                Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType ""  -NotificationRecipientsEmails "$($userEmailAddress)" 
                            }    
                        }
                        
                        $sqlServerDetails = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                    }
                    else
                    {
                        if($_.SqlServerAuditStatus -eq $false)
                        {
                            if($storageAccountType -eq "2")
                            {   #creating storage account for every server
                                $storageAccountName = "storageaccountsqlauditinglogs"+ $countOfStorageAccount
                                $countOfStorageAccount += 1
                                $storageAccountSeperated = New-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $storageAccountName -SkuName Standard_LRS -Location "East US" 
                                if(($storageAccountSeperated|Measure-Object).count -ne 0)
                                {
                                    Write-Host "Storage account $($storageAccountSeperated) is successfully created for SQL Server $($_.ServerName) "
                                }
                                Set-AzSynapseSqlAuditSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountSeperated.Id 
                            }
                            else
                            {
                                Set-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountCentralized.Id     
                            }

                            $sqlServerAuditDetails = Get-AzSynapseSqlAuditSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                            
                            if($sqlServerAuditDetails.BlobStorageTargetState -eq "Enabled" -or $sqlServerAuditDetails.EventHubTargetState -eq "Enabled" -or $sqlServerAuditDetails.LogAnalyticsTargetState -eq "Enabled")
                            {
                                $sqlServerAuditStatus = $true
                            }
                            else
                            {
                                $sqlServerAuditStatus = $false   
                            }
                        }

                        if($hasEmailAddressesAtServer)
                        {
                            $_.IsEmailAccountAdminsConfigured = $isEmailAccountAdminsConfiguredAtserver
                            $_.HasEmailAddresses = $true
                            Update-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType "" 
                        }
                        else
                        {
                            if($_.HasEmailAddresses -eq $true)
                            {
                                Update-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType ""    
                            }
                            else
                            {
                                $userEmailAddresss = $context.Account.Id
                                Update-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType ""  -NotificationRecipientsEmails "$($userEmailAddress)" 
                            }    
                        }

                        $sqlServerDetails = Get-AzSynapseSqlAdvancedThreatProtectionSetting  -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                    }

                    $isAlertPoliciesEnabled = $sqlServerDetails.ThreatDetectionState   
                    $isAlertPoliciesEnabled = $isAlertPoliciesEnabled -eq "Enabled" 
                    $noDisabledAlerts = $sqlServerDetails.ExcludedDetectionTypes.Count 
                    $noDisabledAlerts = $noDisabledAlerts -eq 0 
                    $listofDisabledAlerts = $sqlServerDetails.ExcludedDetectionTypes
                    $listofDisabledAlerts = $listofDisabledAlerts -join ","
                    $isEmailAccountAdminsConfigured = $sqlServerDetails.EmailAdmins
                    $hasEmailAddresses = $sqlServerDetails.NotificationRecipientsEmails.Length
                    $listOfEmailAddress = $sqlServerDetails.NotificationRecipientsEmails
                    $listOfEmailAddress = $listOfEmailAddress -join ","
                    $hasEmailAddresses = $hasEmailAddresses -gt 0

                    if(-not($isEmailAccountAdminsConfigured -or $hasEmailAddresses))
                    {
           
                        if( $ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].Email).Length -ne 0 )
                        {
                            $hasEmailAddresses = $true
                            $ascContactDetails | ForEach-Object {
                                $listOfEmailAddress += $_.Email
                            }
                            $listOfEmailAddress = $listOfEmailAddress -join ","
                        }

                        if( $ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].AlertsToAdmins -eq "on"))
                        {
                            $isEmailAccountAdminsConfigured = $true   
                        }
                    }

                    if ($sqlServerAuditStatus -and $isAlertPoliciesEnabled -and $noDisabledAlerts -and ($isEmailAccountAdminsConfigured -or $hasEmailAddresses))
                    {
                        $remediatedSQLServers += $_ | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                    @{N='ServerName';E={$_.ServerName}},
                                                                    @{N='SqlServerAuditStatus';E={$sqlServerAuditStatus}},
                                                                    @{N='IsAlertPoliciesEnabled';E={$isAlertPoliciesEnabled}},
                                                                    @{N='NoDisabledAlerts';E={$noDisabledAlerts}},
                                                                    @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                    @{N='HasEmailAddresses';E={$hasEmailAddresses}},
                                                                    @{N="ListOfEmailAddresses"; E = {$listOfEmailAddress}},
                                                                    @{N='ListOfDisabledAlerts'; E={$listofDisabledAlerts}}
                    }
                    else
                    {
                        $skippedSQLServers  += $_ | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                  @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                  @{N='ServerName';E={$_.ServerName}},
                                                                  @{N='SqlServerAuditStatus';E={$sqlServerAuditStatus}},
                                                                  @{N='IsAlertPoliciesEnabled';E={$isAlertPoliciesEnabled}},
                                                                  @{N='NoDisabledAlerts';E={$noDisabledAlerts}},
                                                                  @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                  @{N='HasEmailAddresses';E={$hasEmailAddresses}},
                                                                  @{N='ListOfEmailAddresses'; E = {$listOfEmailAddress}},
                                                                  @{N='ListOfDisabledAlerts'; E={$listofDisabledAlerts}}                                              
                    }
                }    
                catch
                {
                    $skippedSQLServers  += $_ 
                                                             
                    Write-Host "Error enabling Advance Threat Protection on SQL Server. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this SQL Server. Advance Threat Protection will not be enabled." -ForegroundColor $([Constants]::MessageType.Info)
                    return
                }
            }
        }

        #if remediation is at server level this block is going to execute
        else
        {
            Write-Host "Enabling advance Threat Protection at individual server" -ForegroundColor $([Constants]::MessageType.Info)
            $sqlServersWithThreatDetectionDisabled  | ForEach-Object{
            
                Write-Host "Fetching SQL Server Resource Id: $($_.ResourceId) for Remediation" 
                try
                {
                    if($_.ResourceGroupName)#Add the condition to check the type of normal SQL Server)
                    {
                        if($_.SqlServerAuditStatus -eq $false)
                        {
                            if($storageAccountType -eq "2")
                            {
                                $storageAccountName = "storageaccountsqlauditinglogs"+ $countOfStorageAccount
                                $countOfStorageAccount += 1
                                $storageAccountSeperated = New-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $storageAccountName -SkuName Standard_LRS -Location "East US"
                                
                                if(($storageAccountSeperated|Measure-Object).count -ne 0)
                                {
                                    Write-Host "Storage account $($storageAccountSeperated) is successfully created for SQL Server $($_.ServerName) "
                                }
                                Set-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountSeperated.Id
                            }
                            else
                            {
                                Set-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountCentralized.Id     
                            }

                            $sqlServerAuditDetails = Get-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                            
                            if($sqlServerAuditDetails.BlobStorageTargetState -eq "Enabled" -or $sqlServerAuditDetails.EventHubTargetState -eq "Enabled" -or $sqlServerAuditDetails.LogAnalyticsTargetState -eq "Enabled")
                            {
                                $sqlServerAuditStatus = $true
                            }
                            else
                            {
                                $sqlServerAuditStatus = $false   
                            }   
                        }

                        if($_.HasEmailAddresses -eq $true)
                        {
                            Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType "" 
                        }
                        else
                        {
                            $userEmailAddress = $context.Account.Id
                            Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType ""  -NotificationRecipientsEmails "$($userEmailAddress)" 
                        }

                        $sqlServerDetails = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                    }
                    else
                    {
                        if($_.SqlServerAuditStatus -eq $false)
                        {
                            if($storageAccountType -eq "2")
                            {
                                $storageAccountName = "storageaccountsqlauditinglogs"+ $countOfStorageAccount
                                $countOfStorageAccount += 1 
                                $storageAccountSeperated = New-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $storageAccountName -SkuName Standard_LRS -Location "East US"
                                Set-AzSynapseSqlAuditSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountSeperated.Id
                            }
                            else
                            {
                                Set-AzSynapseSqlAuditSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccountCentralized.Id   
                            }

                            $sqlServerAuditDetails = Get-AzSynapseSqlAuditSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                           
                            if($sqlServerAuditDetails.BlobStorageTargetState -eq "Enabled" -or $sqlServerAuditDetails.EventHubTargetState -eq "Enabled" -or $sqlServerAuditDetails.LogAnalyticsTargetState -eq "Enabled")
                            {
                                $sqlServerAuditStatus = $true
                            }
                            else
                            {
                                $sqlServerAuditStatus = $false   
                            }   
                        }

                        if($_.HasEmailAddresses -eq $true)
                        {
                           Update-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType "" 
                        }
                        else
                        {
                            $userEmailAddress = $context.Account.Id
                            Update-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ExcludedDetectionType ""  -NotificationRecipientsEmails "$($userEmailAddress)" 
                        }

                        $sqlServerDetails = Get-AzSynapseSqlAdvancedThreatProtectionSetting  -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                    }
                 
                    $isAlertPoliciesEnabled = $sqlServerDetails.ThreatDetectionState   
                    $isAlertPoliciesEnabled = $isAlertPoliciesEnabled -eq "Enabled" 
                    $noDisabledAlerts = $sqlServerDetails.ExcludedDetectionTypes.Count 
                    $noDisabledAlerts = $noDisabledAlerts -eq 0 
                    $listofDisabledAlerts = $sqlServerDetails.ExcludedDetectionTypes
                    $listofDisabledAlerts = $listofDisabledAlerts -join ","
                    $isEmailAccountAdminsConfigured = $sqlServerDetails.EmailAdmins
                    $hasEmailAddresses = $sqlServerDetails.NotificationRecipientsEmails.Length
                    $listOfEmailAddress = $sqlServerDetails.NotificationRecipientsEmails
                    $listOfEmailAddress = $listOfEmailAddress -join ","
                    $hasEmailAddresses = $hasEmailAddresses -gt 0

                    if(-not($isEmailAccountAdminsConfigured -or $hasEmailAddresses))
                    {
         
                        if( $ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].Email).Length -ne 0 )
                        {
                            $hasEmailAddresses = $true
                            $ascContactDetails | ForEach-Object {
                                $listOfEmailAddress += $_.Email
                            }
                            $listOfEmailAddress = $listOfEmailAddress -join ","
                        }
             
                        if( $ascContactDetails.Count -gt 0 -and ($ascContactDetails[0].AlertsToAdmins -eq "on"))
                        {
                            $isEmailAccountAdminsConfigured = $true   
                        }
                    }

                    if ($sqlServerAuditStatus -and $isAlertPoliciesEnabled -and $noDisabledAlerts -and ($isEmailAccountAdminsConfigured -or $hasEmailAddresses ))
                    {
                        $remediatedSQLServers += $_ | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                    @{N='ServerName';E={$_.ServerName}},
                                                                    @{N='SqlServerAuditStatus';E={$sqlServerAuditStatus}},
                                                                    @{N='IsAlertPoliciesEnabled';E={$isAlertPoliciesEnabled}},
                                                                    @{N='NoDisabledAlerts';E={$noDisabledAlerts}},
                                                                    @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                    @{N='HasEmailAddresses';E={$hasEmailAddresses}},
                                                                    @{N="ListOfEmailAddresses"; E = {$listOfEmailAddress}},
                                                                    @{N='ListOfDisabledAlerts'; E={$listofDisabledAlerts}}
                    }
                    else
                    {
                        $skippedSQLServers  += $_ | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                  @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                  @{N='ServerName';E={$_.ServerName}},
                                                                  @{N='SqlServerAuditStatus';E={$sqlServerAuditStatus}},
                                                                  @{N='IsAlertPoliciesEnabled';E={$isAlertPoliciesEnabled}},
                                                                  @{N='NoDisabledAlerts';E={$noDisabledAlerts}},
                                                                  @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                  @{N='HasEmailAddresses';E={$hasEmailAddresses}},
                                                                  @{N="ListOfEmailAddresses"; E = {$listOfEmailAddress}},
                                                                  @{N='ListOfDisabledAlerts'; E={$listofDisabledAlerts}}                                             
                    }   
                }
                catch
                {
                    $skippedSQLServers  += $_ 
                    Write-Host "Error enabling Advance Threat Protection on SQL Server. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this SQL Server. Advance Threat Protection will not be enabled." -ForegroundColor $([Constants]::MessageType.Info)
                    return
                }
            }
        }
      
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($remediatedSQLServers | Measure-Object).Count -gt 0)
        {
            Write-Host "Advance Threat Protection successfully enabled for the following SQL Server (s):" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedSQLServers | Format-Table -property ResourceGroupName , ServerName

            # Write this to a file.
            $remediatedSQLServersFile = "$($backupFolderPath)\RemediatedSQLServers.csv"
            $remediatedSQLServers | Export-CSV -Path $remediatedSQLServersFile -NoTypeInformation
            Write-Host "This information has been saved to $($remediatedSQLServersFile)"
        }

        if ($($skippedSQLServers | Measure-Object).Count -gt 0)
        {
            Write-Host "Error occurred while enabling Advance Threat Protection for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedSQLServers |  Format-Table -property ResourceGroupName , ServerName
            
            # Write this to a file.
            $skippedSQLServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
            $skippedSQLServers | Export-CSV -Path $skippedSQLServersFile -NoTypeInformation
            Write-Host "This information has been saved to $($skippedSQLServersFile)"
        }    
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] SQL Server  details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`nRun the same command with -FilePath $($backupFile) and without -DryRun, to enable Advance Threat Protection for all SQL Servers listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }
}

# Defines commonly used constants.
class Constants
{
    # Defines commonly used colour codes, corresponding to the severity of the log.
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}
