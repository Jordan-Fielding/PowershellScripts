Write-Host "Please input your Partner account to login"
$UPN = "jordanf@centra.com.au"
$csvFile = "C:\Files\Test.csv"
Connect-MsolService
$tenantIds = Get-MsolPartnerContract -All | Select-Object -ExpandProperty TenantId
$headerOrder = 'CompanyName', 'Identity', 'Name', 'MarkAsSpamNdrBackscatter', 'MarkAsSpamSpfRecordHardFail', 'MarkAsSpamFromAddressAuthFail', 'SpamQuarantineTag', 'HighConfidenceSpamQuarantineTag', 'PhishQuarantineTag', 'HighConfidencePhishQuarantineTag', 'BulkQuarantineTag'

$Spam = Get-HostedContentFilterPolicy
$Malware = Get-MalwareFilterPolicy
$Quarantine = Get-QuarantinePolicy
$Domain = Get-AcceptedDomain
$DKIM = Get-DkimSigningConfig
Function GetProperties {
$properties = @{
'Spam - Company Domain' = $CustomerDomain
'Spam - Identity' = $Spam.Identity
'Spam - MarkAsSpamNdrBackscatter' = $Spam.MarkAsSpamNdrBackscatter
'Spam - MarkAsSpamSpfRecordHardFail' = $Spam.MarkAsSpamSpfRecordHardFail
'Spam - MarkAsSpamFromAddressAuthFail' = $Spam.MarkAsSpamFromAddressAuthFail
'Spam - SpamQuarantineTag' = $Spam.SpamQuarantineTag
'Spam - HighConfidenceSpamQuarantineTag' = $Spam.HighConfidenceSpamQuarantineTag
'Spam - PhishQuarantineTag' = $Spam.PhishQuarantineTag
'Spam - HighConfidencePhishQuarantineTag' = $Spam.HighConfidencePhishQuarantineTag
'Spam - BulkQuarantineTag' = $Spam.BulkQuarantineTag
'Malware - Identity' = $Malware.Name
'Malware - Common Attachment Types Filter' = $Malware.EnableFileFilter
'Malware - Policy Created' = $Malware.WhenCreated
'Malware - Policy Last Changed' = $Malware.WhenChanged
'Malware - Quaratine Tag' = $Malware.QuarantineTag
'Quarantine - Identity' = $Quarantine.Name
'Quarantine - End User Permissions' = $Quarantine.EndUserQuarantinePermissions
'Quarantine - Notification' = $Quarantine.ESNEnabled
'Domain - Domain Name' = $Domain.Name
'Domain - Domain Enabled?' = $Domain.IsValid
'DKIM - Identity' = $DKIM.Name
'DKIM - Enabled' = $DKIM.Enabled
}
}

# If the file doesn't exist, create it and add the header row
if (!(Test-Path $csvFile)) {
    $header = $properties.Keys -join ','
    $header | Out-File $csvFile -Encoding utf8
}

# Output the properties to the CSV file
$values = $properties.Values -join ','
$values | Out-File $csvFile -Encoding utf8 -Append

# Output the properties to the CSV file
foreach ($tenantId in $tenantIds) {
    $CustomerDomains = Get-MsolDomain -TenantId $tenantId | Where-Object { $_.Name.EndsWith(".onmicrosoft.com") } | Select-Object -ExpandProperty Name

    foreach ($CustomerDomain in $CustomerDomains) {
        Connect-ExchangeOnline -UserPrincipalName $UPN -DelegatedOrganization $CustomerDomain

        $Exportporperties = GetProperties

# Output the properties to the CSV file in the order specified by $headerOrder
$values = $headerOrder | ForEach-Object { $Exportporperties[$_]}
$values = $values -join ','
$values | Out-File $csvFile -Encoding utf8 -Append
        
    }
}


 




