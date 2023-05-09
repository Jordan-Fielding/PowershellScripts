



Function GetClientDetails {
    Write-Host "What is the Companys Name? (Keep Name as a Whole Word, No Spaces)" -ForegroundColor Black -BackgroundColor Yellow
    $companyName = Read-Host "Name:"
}


# This will Set the following Settings 
# Backscatter = On | SPF Hard Fail = On | Spam from Address Auth Fail = On | Quaratine Tags for all actions | Actions for Quaratine
Function SpamPolicy {
    Set-HostedContentFilterPolicy -Identity "Default" -MarkAsSpamNdrBackscatter On -MarkAsSpamSpfRecordHardFail On -MarkAsSpamFromAddressAuthFail On -SpamQuarantineTag $QuaratineName -HighConfidenceSpamQuarantineTag $QuaratineName -PhishQuarantineTag $QuaratineName -HighConfidencePhishQuarantineTag $QuaratineName -BulkQuarantineTag $QuaratineName -HighConfidencePhishAction Quarantine -BulkSpamAction MoveToJmf -HighConfidenceSpamAction Quarantine -PhishSpamAction Quarantine -SpamAction MoveToJmf
}


# This will setup the Quaratine Policy with the <CompanyName>DefaultPolicy | End user Notifications to True | And allow the user too:
# PermissionToAllowSender | PermissionToBlockSender | PermissionToRelease | PermissionToPreview | PermissionToDelete
Function QuaratinePolicy {
    $QuarantineName = "$companyName"+"DefaultPolicy"
if (Get-QuarantinePolicy -Identity $QuarantineName) {
    Write-host "Yes $quarantineName"
}
if (-not (Get-QuarantinePolicy -Identity $QuarantineName)) {
    Write-Host "No"
}

# Set-QuarantinePolicy -Name $QuaratineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
}
Connect-ExchangeOnline

GetClientDetails

QuaratinePolicy

# SpamPolicy