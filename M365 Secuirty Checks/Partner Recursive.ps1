

Function ConnectTo-EXO {
    # Check if MS EXO module is installed
    if (-not(Get-InstalledModule ExchangeOnlineManagement)) { 
        Write-Host "Microsoft EXO module not found" -ForegroundColor Black -BackgroundColor Yellow
        $install = Read-Host "Do you want to install the Microsoft EXO Module?"

        if ($install -match "[yY]") {
            Install-Module ExchangeOnlineManagement -Repository PSGallery -Scope CurrentUser -AllowClobber -Force
        }
        else {
            Write-Host "Microsoft EXO module is required." -ForegroundColor Black -BackgroundColor Yellow
            exit
        } 
    }
    #    # Connect to EXO
    #    Write-Host "Connecting to Microsoft EXO" -ForegroundColor Cyan
    #    Connect-exchangeonline
}
Function ConnectTo-MSOnline {
    # Check if MS Msol module is installed
    if (-not(Get-InstalledModule MSOnline)) { 
        Write-Host "Microsoft Msol module not found" -ForegroundColor Black -BackgroundColor Yellow
        $install = Read-Host "Do you want to install the Microsoft Msol Module?"

        if ($install -match "[yY]") {
            Install-Module MSOnline
        }
        else {
            Write-Host "Microsoft Msol module is required." -ForegroundColor Black -BackgroundColor Yellow
            exit
        } 
    }
   # Connect to EXO
   Write-Host "Connecting to Microsoft Msol" -ForegroundColor Cyan
   Connect-MsolService
}
Function ConnectTo-DMARC {
    # Check if Microsoft DomainHealthChecker module is installed
    if (-not(Get-InstalledModule DomainHealthChecker)) { 
        Write-Host "Microsoft DomainHealthChecker module not found" -ForegroundColor Black -BackgroundColor Yellow
        $install = Read-Host "Do you want to install the DomainHealthChecker?"

        if ($install -match "[yY]") {
            Install-Module DomainHealthChecker -Repository PSGallery -Scope CurrentUser -AllowClobber -Force
        }
        else {
            Write-Host "Microsoft DomainHealthChecker module is required." -ForegroundColor Black -BackgroundColor Yellow
            exit
        } 
    }
}

Function Change-TenantData {
    $ScriptBlock = {
        param (
            [string]$CustomerDomain,
            [string]$UPN
        )

        try {
            Connect-ExchangeOnline -UserPrincipalName $UPN -DelegatedOrganization $CustomerDomain
            Enable-OrganizationCustomization
            $companyName = Get-OrganizationConfig | Select-Object -ExpandProperty Displayname

            
            #Quaratine Policy 
            $QuarantineName = "$companyName "+"DefaultPolicy"
            if (Get-QuarantinePolicy -Identity $QuarantineName) {
                Set-QuarantinePolicy -Name $QuarantineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
            }
            if (-not (Get-QuarantinePolicy -Identity $QuarantineName)) {
                New-QuarantinePolicy -Name $QuarantineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
            }

            #Spam Policy
            Set-HostedContentFilterPolicy -Identity "Default" -MarkAsSpamNdrBackscatter On -MarkAsSpamSpfRecordHardFail On -MarkAsSpamFromAddressAuthFail On -SpamQuarantineTag $QuarantineName -HighConfidenceSpamQuarantineTag $QuarantineName -PhishQuarantineTag $QuarantineName -HighConfidencePhishQuarantineTag $QuarantineName -BulkQuarantineTag $QuarantineName -HighConfidencePhishAction Quarantine -BulkSpamAction MoveToJmf -HighConfidenceSpamAction Quarantine -PhishSpamAction Quarantine -SpamAction MoveToJmf
            
            #Malware Policy
            Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $true -QuarantineTag $QuarantineName
            
        
            
            Start-Sleep -Milliseconds 50
            
        
            }
            catch {
                Write-Host "Error occurred for tenant: $CustomerDomain"
                Write-Host $_.Exception.Message
            }
            
        }
    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $CustomerDomain, $UPN,
    $Job | Wait-Job | Receive-Job
}
Function Get-TenantData {
    
    
    $ScriptBlock = {
        param (
            [string]$CustomerDomain,
            [string]$UPN,
            [string]$csvFile,
            [int]$TenantNo,
            [int]$CustomerCount
        )

        try {
            Connect-ExchangeOnline -UserPrincipalName $UPN -DelegatedOrganization $CustomerDomain
            $Spam = Get-HostedContentFilterPolicy
            $Malware = Get-MalwareFilterPolicy
            $Quarantine = Get-QuarantinePolicy
            $DKIM = Get-DkimSigningConfig
            $Domain = Get-AcceptedDomain
        # $DMARC = foreach ($Domain in $Domains) {
            # (Get-DMARCRecord  $Domain) }
            [pscustomobject]@{
            'Spam - Company Domain' = ($CustomerDomain -join ', ')
            'Spam - Identity' = ($Spam.Identity -join ', ')
            'Spam - MarkAsSpamNdrBackscatter' = ($Spam.MarkAsSpamNdrBackscatter -join ', ')
            'Spam - MarkAsSpamSpfRecordHardFail' = ($Spam.MarkAsSpamSpfRecordHardFail -join ', ')
            'Spam - MarkAsSpamFromAddressAuthFail' = ($Spam.MarkAsSpamFromAddressAuthFail -join ', ')
            'Spam - SpamQuarantineTag' = ($Spam.SpamQuarantineTag -join ', ')
            'Spam - HighConfidenceSpamQuarantineTag' = ($Spam.HighConfidenceSpamQuarantineTag -join ', ')
            'Spam - PhishQuarantineTag' = ($Spam.PhishQuarantineTag -join ', ')
            'Spam - HighConfidencePhishQuarantineTag' = ($Spam.HighConfidencePhishQuarantineTag -join ', ')
            'Spam - BulkQuarantineTag' = ($Spam.BulkQuarantineTag -join ', ')
            'Malware - Identity' = ($Malware.Name -join ', ')
            'Malware - Common Attachment Types Filter' = ($Malware.EnableFileFilter -join ', ')
            'Malware - Policy Created' = ($Malware.WhenCreated -join ', ')
            'Malware - Policy Last Changed' = ($Malware.WhenChanged -join ', ')
            'Malware - Quaratine Tag' = ($Malware.QuarantineTag -join ', ')
            'Quarantine - Identity' = ($Quarantine.Name -join ', ')
            'Quarantine - End User Permissions' = ($Quarantine.EndUserQuarantinePermissions -join ';')
            'Quarantine - Notification' = ($Quarantine.ESNEnabled -join ', ')
            'Domain - Domain Name' = ($Domain.Name -join ', ')
            'Domain - Domain Enabled?' = ($Domain.IsValid -join ', ')
            'DKIM - Identity' = ($DKIM.Name -join ', ')
            'DKIM - Enabled' = ($DKIM.Enabled -join ', ')
            # 'DMARC - DMARC' = ($DMARC -join ', ')
            }| Export-CSV -Path $csvFile -NoTypeInformation -Append
            
            
            Start-Sleep -Milliseconds 50
            
        
            }
            catch {
                Write-Host "Error occurred for tenant: $CustomerDomain"
                Write-Host $_.Exception.Message
            }
            
        }
    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $CustomerDomain, $UPN, $csvFile, $CustomerCount, $TenantNo
    $Job | Wait-Job | Receive-Job
}

            
Function Mainscript {

    
    Process {
    Write-Host "Which Tool would you like to run? `nSecurity Report: 1`nSecurity Change: 2" -ForegroundColor Black -BackgroundColor Yellow
    $answer = Read-Host "Selection:"
    if($answer -match "[1]") {
    # Create the directory if it doesn't exist
    
    # Output the properties to the CSV file
    $batchSize = 10  # Set the desired batch siz
    # Split the array into smaller chunks$
    $chunks = for ($i = 0; $i -lt $TenantIds.Count; $i += $batchSize) {
    $TenantIds[$i..($i + $batchSize - 1)]
}
    foreach ($chunk in $chunks) {
    $CustomerDomains = Get-MsolDomain -TenantId $chunk | Where-Object { $_.Name.EndsWith(".onmicrosoft.com") } | Select-Object -ExpandProperty Name
    

    foreach ($CustomerDomain in $CustomerDomains) {
        
            Write-Progress -Activity "Processing Users" -Status "Customer Number $TenantNo / $CustomerCount"
           Get-TenantData -CustomerDomain $CustomerDomain -UPN $UPN -csvFile $csvFile -tenantIds $tenantIds
            $TenantNo++

            }

        }

    }
    if($answer -match "[2]") {
         # Create the directory if it doesn't exist
    
    # Output the properties to the CSV file
    $batchSize = 10  # Set the desired batch siz
    # Split the array into smaller chunks$
    $chunks = for ($i = 0; $i -lt $TenantIds.Count; $i += $batchSize) {
    $TenantIds[$i..($i + $batchSize - 1)]
}
    foreach ($chunk in $chunks) {
    $CustomerDomains = Get-MsolDomain -TenantId $chunk | Where-Object { $_.Name.EndsWith(".onmicrosoft.com") } | Select-Object -ExpandProperty Name
    

    foreach ($CustomerDomain in $CustomerDomains) {
        
             # Create the directory if it doesn't exist
    
    # Output the properties to the CSV file
    $batchSize = 10  # Set the desired batch siz
    # Split the array into smaller chunks$
    $chunks = for ($i = 0; $i -lt $TenantIds.Count; $i += $batchSize) {
    $TenantIds[$i..($i + $batchSize - 1)]
}
    foreach ($chunk in $chunks) {
    $CustomerDomains = Get-MsolDomain -TenantId $chunk | Where-Object { $_.Name.EndsWith(".onmicrosoft.com") } | Select-Object -ExpandProperty Name
    

    foreach ($CustomerDomain in $CustomerDomains) {
        
            Write-Progress -Activity "Processing Users" -Status "Customer Number $TenantNo / $CustomerDomain"
           Change-TenantData -CustomerDomain $CustomerDomain -UPN $UPN
            $TenantNo++

            }

        }

            }

        }
    }
    }
}

# ConnectTo-DMARC
$UPN = Read-Host "What is your email?"
$TenantNo = 1
$CustomerCount = $tenantIds.count
$csvFile = "C:\Files\SecurityExport.csv"
$directory = Split-Path -Path $csvFile
    if (-not (Test-Path -Path $directory)) {
    New-Item -ItemType Directory -Path $directory | Out-Null
    }
ConnectTo-MSOnline
ConnectTo-EXO
$tenantIds = Get-MsolPartnerContract -All | Select-Object -ExpandProperty TenantId
# Mainscript
Mainscript




