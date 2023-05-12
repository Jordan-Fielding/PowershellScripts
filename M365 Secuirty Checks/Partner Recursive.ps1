# # Connect-MsolService

# # Get all partner contracts and select the TenantId property
# $tenantIds = Get-MsolPartnerContract -All | Select-Object -ExpandProperty TenantId

# Initialize the CSV file with headers
$csvFile = "C:\Files\Test.csv"
"CompanyName,PolicyName,MarkAsSpamNdrBackscatter,MarkAsSpamSpfRecordHardFail,MarkAsSpamFromAddressAuthFail,SpamQuarantineTag,HighConfidenceSpamQuarantineTag,PhishQuarantineTag,HighConfidencePhishQuarantineTag,BulkQuarantineTag" | Set-Content $csvFile

# # Connect to Exchange Online using modern authentication
Connect-ExchangeOnline -UserPrincipalName "" # Replace <UPN> with your user principal name

# # Loop through each tenant ID and retrieve the domains that end in .onmicrosoft.com
$results = foreach ($tenantId in $tenantIds) {
    $CustomerDomains = Get-MsolDomain -TenantId $tenantId | Where-Object { $_.Name.EndsWith(".onmicrosoft.com") } | Select-Object -ExpandProperty Name
    foreach ($CustomerDomain in $CustomerDomains) {
        Connect-ExchangeOnline -UserPrincipalName "" -DelegatedOrganization $CustomerDomain
        
$Spam = Get-HostedContentFilterPolicy -Identity "Default"
$properties = @{
    'CompanyName' = $CustomerDomain
    'Identity' = $Spam.Identity
    'Name' = $Spam.Name
    'MarkAsSpamNdrBackscatter' = $Spam.MarkAsSpamNdrBackscatter
    'MarkAsSpamSpfRecordHardFail' = $Spam.MarkAsSpamSpfRecordHardFail
    'MarkAsSpamFromAddressAuthFail' = $Spam.MarkAsSpamFromAddressAuthFail
    'SpamQuarantineTag' = $Spam.SpamQuarantineTag
    'HighConfidenceSpamQuarantineTag' = $Spam.HighConfidenceSpamQuarantineTag
    'PhishQuarantineTag' = $Spam.PhishQuarantineTag
    'HighConfidencePhishQuarantineTag' = $Spam.HighConfidencePhishQuarantineTag
    'BulkQuarantineTag' = $Spam.BulkQuarantineTag
}
$csvRow = New-Object -TypeName psobject -Property $properties
$csvRow | Select-Object * | Export-Csv -Path $csvFile -Append -NoTypeInformation -Force

    }
}

 




