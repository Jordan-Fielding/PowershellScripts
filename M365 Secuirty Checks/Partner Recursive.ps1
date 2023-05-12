Write-Host "Please input your Partner account to login"
$UPN = "jordanf@centra.com.au"
$csvFile = "C:\Files\Test.csv"
# "Spam - Company Domain,Spam - Identity,Spam - MarkAsSpamNdrBackscatter,Spam - MarkAsSpamSpfRecordHardFail,Spam - MarkAsSpamFromAddressAuthFail,Spam - SpamQuarantineTag,Spam - HighConfidenceSpamQuarantineTag,Spam - PhishQuarantineTag,Spam - HighConfidencePhishQuarantineTag,Spam - BulkQuarantineTag,Malware - Identity,Malware - Common Attachment Types Filter,Malware - Policy Created,Malware - Policy Last Changed,Malware - Quaratine Tag,Quarantine - Identity,Quarantine - End User Permissions,Quarantine - Notification" | Set-Content $csvFile
Connect-MsolService
$tenantIds = Get-MsolPartnerContract -All | Select-Object -ExpandProperty TenantId

Function ConnectTo-DMARC {
    # Check if MS Graph module is installed
    if (-not(Get-InstalledModule DomainHealthChecker)) { 
        Write-Host "Microsoft DomainHealthChecker module not found" -ForegroundColor Black -BackgroundColor Yellow
        $install = Read-Host "Do you want to install the Microsoft EXO Module?"

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
# Output the properties to the CSV file
foreach ($tenantId in $tenantIds) {
    $CustomerDomains = Get-MsolDomain -TenantId $tenantId | Where-Object { $_.Name.EndsWith(".onmicrosoft.com") } | Select-Object -ExpandProperty Name

    foreach ($CustomerDomain in $CustomerDomains) {
        Connect-ExchangeOnline -UserPrincipalName $UPN -DelegatedOrganization $CustomerDomain
        $Spam = Get-HostedContentFilterPolicy
        $MalwareProcess = Get-MalwareFilterPolicy
        $Quarantine = Get-QuarantinePolicy
        $Domain = Get-AcceptedDomain
        $DKIM = Get-DkimSigningConfig
        [pscustomobject]@{
            'Spam - Company Domain' = ($CustomerDomain -join ', ')
            'Spam - Identity' = ($Spam.Identity -join ', ')
            'Spam - MarkAsSpamNdrBackscatter' = $Spam.MarkAsSpamNdrBackscatter
            'Spam - MarkAsSpamSpfRecordHardFail' = $Spam.MarkAsSpamSpfRecordHardFail
            'Spam - MarkAsSpamFromAddressAuthFail' = $Spam.MarkAsSpamFromAddressAuthFail
            'Spam - SpamQuarantineTag' = $Spam.SpamQuarantineTag
            'Spam - HighConfidenceSpamQuarantineTag' = $Spam.HighConfidenceSpamQuarantineTag
            'Spam - PhishQuarantineTag' = $Spam.PhishQuarantineTag
            'Spam - HighConfidencePhishQuarantineTag' = $Spam.HighConfidencePhishQuarantineTag
            'Spam - BulkQuarantineTag' = $Spam.BulkQuarantineTag
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
            # 'DMARC - DMARC' = $d = Get-AcceptedDomain
        }
    }
    }

    }
}
ConnectTo-DMARC
Mainscript | Export-CSV -Path $csvFile -NoTypeInformation

 




