# This will Set the following Settings 
# Backscatter = On | SPF Hard Fail = On | Spam from Address Auth Fail = On | Quaratine Tags for all actions | Actions for Quaratine
Function SpamPolicy {
    #Specifies the Command to use for Checking
    $SpamPolicy = Get-HostedContentFilterPolicy -Identity "Default"
    #Specifies the settings and Values that needto be set
    $settingsToCheck = @{
        MarkAsSpamNdrBackscatter = "On"
        MarkAsSpamSpfRecordHardFail = "On"
        MarkAsSpamFromAddressAuthFail = "On"
        SpamQuarantineTag = "$QuarantineName"
        HighConfidenceSpamQuarantineTag = "$QuarantineName"
        PhishQuarantineTag = "$QuarantineName"
        HighConfidencePhishQuarantineTag = "$QuarantineName"
        BulkQuarantineTag = "$QuarantineName"
        HighConfidencePhishAction = "Quarantine"
        BulkSpamAction = "MoveToJmf"
        HighConfidenceSpamAction = "Quarantine"
        PhishSpamAction = "Quarantine"
        SpamAction = "MoveToJmf"
    }
    #Loops through each setting and checks if it is enabled, if not it enables it
    foreach ($setting in $settingsToCheck.GetEnumerator()) {
        $property = $setting.Key
        $message = $setting.Value
        if ($SpamPolicy.$property -notmatch "$message") {
            Write-Host "$property not enabled, Enabling now...."
            $param = @{ Identity = "Default" }
            $param.$property = "$message"
            Set-HostedContentFilterPolicy @param
        }
    }

    Write-Host "All Settings Enabled!"
}
Function MalwarePolicy {
    #Malware Policy
    Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $true -QuarantineTag "SSSAus DefaultPolicy"
}

Function PhishingPolicy{
    $accountSKU = Get-MsolAccountSku | Where-Object {$_.AccountSkuId -like "ATP_ENTERPRISE"}
    if($accountSKU -ne $null){

    }
    if($accountSKU -eq $null){
        
    }

}

# This will setup the Quaratine Policy with the <CompanyName>DefaultPolicy | End user Notifications to True | And allow the user too:
# PermissionToAllowSender | PermissionToBlockSender | PermissionToRelease | PermissionToPreview | PermissionToDelete
Function QuaratinePolicy {
#Quaratine Policy 
$QuarantineName = "$companyName "+"DefaultPolicy"
$QuarantinePolicy = Get-QuarantinePolicy -Identity $QuarantineName
if ($QuarantinePolicy -match "$QuarantineName") {
    Set-QuarantinePolicy -Identity $QuarantineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
}
if ($QuarantinePolicy -notmatch "$QuarantineName") {
    New-QuarantinePolicy -Name $QuarantineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
}

# Set-QuarantinePolicy -Name $QuaratineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true
}
Connect-MsolService
Connect-ExchangeOnline


Write-Host "What is the Companys Name? (Keep Name as a Whole Word, No Spaces)" -ForegroundColor Black -BackgroundColor Yellow
$companyName = Read-Host "Name:"
#Runs Tests and Checks
QuaratinePolicy
SpamPolicy
MalwarePolicy