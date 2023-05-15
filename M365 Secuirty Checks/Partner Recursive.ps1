

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
Function Mainscript {
    
    Process {
    # Create the directory if it doesn't exist
    $TenantNo = 1
    # Output the properties to the CSV file
    foreach ($tenantId in $tenantIds) {
    $CustomerDomains = Get-MsolDomain -TenantId $tenantId | Where-Object { $_.Name.EndsWith(".onmicrosoft.com") } | Select-Object -ExpandProperty Name

    foreach ($CustomerDomain in $CustomerDomains) {
        Connect-ExchangeOnline -UserPrincipalName $UPN -DelegatedOrganization $CustomerDomain
        $Spam = Get-HostedContentFilterPolicy
        $Malware = Get-MalwareFilterPolicy
        $Quarantine = Get-QuarantinePolicy
        $DKIM = Get-DkimSigningConfig
        # $Domains = Get-AcceptedDomain
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
            'Quarantine - End User Permissions' = ($Quarantine.EndUserQuarantinePermissions -join ', ')
            'Quarantine - Notification' = ($Quarantine.ESNEnabled -join ', ')
            'Domain - Domain Name' = ($Domain.Name -join ', ')
            'Domain - Domain Enabled?' = ($Domain.IsValid -join ', ')
            'DKIM - Identity' = ($DKIM.Name -join ', ')
            'DKIM - Enabled' = ($DKIM.Enabled -join ', ')
            # 'DMARC - DMARC' = ($DMARC -join ', ')
            }
        Write-Progress -Activity "Processing Users" -Status "Customer Number $TenantNo"
        Start-Sleep -Milliseconds 50
        $TenantNo++
        }
    }
    }

    }

# ConnectTo-DMARC
$UPN = Read-Host "What is your email?"
$csvFile = "C:\Files\Test.csv"
$directory = Split-Path -Path $csvFile
    if (-not (Test-Path -Path $directory)) {
    New-Item -ItemType Directory -Path $directory | Out-Null
    }
ConnectTo-MSOnline
ConnectTo-EXO
$tenantIds = Get-MsolPartnerContract -All | Select-Object -ExpandProperty TenantId
Mainscript | Export-CSV -Path $csvFile -NoTypeInformation




