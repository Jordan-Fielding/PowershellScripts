



Function GetClientDetails {
    Write-Host "What is the Companys Name? (Keep Name as a Whole Word, No Spaces)" -ForegroundColor Black -BackgroundColor Yellow
    $companyName = Read-Host "Name:"
}

# This will Set the following Settings 
# Backscatter = On | SPF Hard Fail = On | Spam from Address Auth Fail = On | Quaratine Tags for all actions | Actions for Quaratine
Function SpamPolicy {
    Set-HostedContentFilterPolicy -Identity "Default" -MarkAsSpamNdrBackscatter On -MarkAsSpamSpfRecordHardFail On -MarkAsSpamFromAddressAuthFail On -SpamQuarantineTag $QuarantineName -HighConfidenceSpamQuarantineTag $QuarantineName -PhishQuarantineTag $QuarantineName -HighConfidencePhishQuarantineTag $QuarantineName -BulkQuarantineTag $QuarantineName -HighConfidencePhishAction Quarantine -BulkSpamAction MoveToJmf -HighConfidenceSpamAction Quarantine -PhishSpamAction Quarantine -SpamAction MoveToJmf
}

Function MalwarePolicy {
    #Malware Policy
    Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $true -QuarantineTag "SSSAus DefaultPolicy"
}

# This will setup the Quaratine Policy with the <CompanyName>DefaultPolicy | End user Notifications to True | And allow the user too:
# PermissionToAllowSender | PermissionToBlockSender | PermissionToRelease | PermissionToPreview | PermissionToDelete
Function QuaratinePolicy {
#Quaratine Policy 
$QuarantineName = "$companyName "+"DefaultPolicy"
if (Get-QuarantinePolicy -Identity $QuarantineName) {
    Set-QuarantinePolicy -Name $QuarantineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
}
if (-not (Get-QuarantinePolicy -Identity $QuarantineName)) {
    New-QuarantinePolicy -Name "SSSAus DefaultPolicy" -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
}

# Set-QuarantinePolicy -Name $QuaratineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
}
Connect-ExchangeOnline

GetClientDetails

QuaratinePolicy
SpamPolicy
MalwarePolicy

# SpamPolicy