# This will Set the following Settings 
# Backscatter = On | SPF Hard Fail = On | Spam from Address Auth Fail = On | Quaratine Tags for all actions | Actions for Quaratine
Function SpamPolicy {
    #Specifies the Command to use for Checking
    $SpamPolicy = Get-HostedContentFilterPolicy -Identity "Default"
    #Specifies the settings and Values that needto be set
    $SpamsettingsToCheck = @{
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
    foreach ($setting in $SpamsettingsToCheck.GetEnumerator()) {
        $property = $setting.Key
        $message = $setting.Value
        if ($SpamPolicy.$property -notmatch "$message") {
            Write-Host "$property not enabled, Enabling now...."
            $param = @{ Identity = "Default" }
            $param.$property = "$message"
            Set-HostedContentFilterPolicy @param
        }
    }

    Write-Host "All Spam Settings Enabled!"
}
Function MalwarePolicy {
    #Malware Policy
    Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $true -QuarantineTag "SSSAus DefaultPolicy"
}

Function PhishingPolicy {
    $PhishingPolicy = Get-AntiPhishPolicy -Identity "Office365 AntiPhish Default"
    $accountSKU = Get-MsolAccountSku | Where-Object {$_.AccountSkuId -like "*ATP_ENTERPRISE*"}

    
    if($accountSKU -ne $null){
        $PhishATPsettingsToCheck = @{
            PhishThresholdLevel = 1
            EnableFirstContactSafetyTips = $true
            EnableMailboxIntelligence = $true
            EnableMailboxIntelligenceProtection = $true
            EnableOrganizationDomainsProtection = $true
            EnableSimilarDomainsSafetyTips = $true
            EnableSimilarUsersSafetyTips = $true
            EnableSpoofIntelligence = $true
            EnableTargetedDomainsProtection = $true
            EnableTargetedUserProtection = $true
            EnableUnauthenticatedSender = $true
            EnableUnusualCharactersSafetyTips = $true
            EnableViaTag = $true
            HonorDmarcPolicy = $true
            MailboxIntelligenceProtectionAction = "Quarantine"
            MailboxIntelligenceQuarantineTag = "$QuarantineName"
            SpoofQuarantineTag = "$QuarantineName"
            TargetedDomainProtectionAction = "Quarantine"
            TargetedDomainQuarantineTag = "$QuarantineName"
            TargetedUserProtectionAction = "Quarantine"
            TargetedUserQuarantineTag = "$QuarantineName"

        }
        
        foreach ($PhishATPsetting in $PhishATPsettingsToCheck.GetEnumerator()) {
            $PhishATPproperty = $PhishATPsetting.Key
            $PhishATPmessage = $PhishATPsetting.Value
            if ($PhishingPolicy.$PhishATPproperty -notmatch "$PhishATPmessage") {
                Write-Host "$PhishATPproperty not enabled, Enabling now...."
                $PhishATPparam = @{ Identity = "Office365 AntiPhish Default" }
                $PhishATPparam.$PhishATPproperty = $PhishATPmessage
                Set-AntiPhishPolicy @PhishATPparam
            }
        }
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -TargetedDomainsToProtect $domain
            Write-Host "Protecting Domain $domain"
            }
            
        }
    }
    if($accountSKU -eq $null){
        
        $PhishsettingsToCheck = @{
            EnableSpoofIntelligence = $true
            EnableFirstContactSafetyTips = $true
            EnableViaTag = $true
            EnableUnauthenticatedSender = $true
            AuthenticationFailAction = "Quarantine"
            DmarcRejectAction = "Quarantine"
            DmarcQuarantineAction = "Quarantine"
            SpoofQuarantineTag = "$QuarantineName"
        }
        foreach ($Phishsetting in $PhishsettingsToCheck.GetEnumerator()) {
            $Phishproperty = $Phishsetting.Key
            $Phishmessage = $Phishsetting.Value
            if ($PhishingPolicy.$Phishproperty -notmatch $Phishmessage) {
                Write-Host "$Phishproperty not enabled, Enabling now...."
                $Phishparam = @{ Identity = "Office365 AntiPhish Default" }
                $Phishparam.$Phishproperty = $Phishmessage
                Set-AntiPhishPolicy @Phishparam
            }
        

    }
    
    Write-Host "All Phishing Settings Enabled!"
}

Function SafeAttachmentsPolicy {
    $SafeAttachmentsName = "$companyName "+"DefaultPolicy"
    $SafeAttachmentsPolicy = Get-SafeAttachmentPolicy | Where-Object {$_.Identity -like "*Jorbella DefaultPolicy*"}
    if ($SafeAttachmentsPolicy -ne $null) {
        $SafeAttachmentssettingsToCheck = @{
            Action = "DynamicDelivery"
            ActionOnError = $true
            QuarantineTag = "$QuarantineName"
            Enable  = $true
        }
        foreach ($SAsetting in $SafeAttachmentssettingsToCheck.GetEnumerator()) {
            $SAproperty = $SAsetting.Key
            $SAmessage = $SAsetting.Value
            if ($SafeAttachmentsPolicy.$SAproperty -notmatch $SAmessage) {
                Write-Host "$SAproperty not enabled, Enabling now...."
                $SAparam = @{ Identity = "$SafeAttachmentsName" }
                $SAparam.$SAproperty = $SAmessage
                Set-SafeAttachmentPolicy @SAparam
            }
        }
    }
    if ($SafeAttachmentsPolicy -eq $null) {
        New-SafeAttachmentPolicy -Action "DynamicDelivery" -ActionOnError $true -QuarantineTag "$QuarantineName" -Enable $true
    }
    Write-Host "All Safe Attachment Settings Enabled!"
}
Function SafeAttachmentsRule {
    $SafeAttachmentsRuleName = "$companyName "+"DefaultPolicy"
    $SafeAttachmentsRule = Get-SafeAttachmentRule | Where-Object {$_.Identity -like "*Jorbella DefaultPolicy*"}

    if ($SafeAttachmentsRule -ne $null) {
        
        $SafeAttachmentsRulesettingsToCheck = @{
            SafeAttachmentPolicy = "$SafeAttachmentsName"

        }
        foreach ($SARsetting in $SafeAttachmentsRulesettingsToCheck.GetEnumerator()) {
            $SARproperty = $SARsetting.Key
            $SARmessage = $SARsetting.Value
            if ($SafeAttachmentseRule.$SARproperty -notmatch $SARmessage) {
                Write-Host "$SARproperty not enabled, Enabling now...."
                $SARparam = @{ Identity = "$SafeAttachmentsRuleName" }
                $SARparam.$SARproperty = $SARmessage
                Set-SafeAttachmentRule @SARparam
            }
        }
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            
            Set-SafeAttachmentRule -Identity $SafeAttachmentsRuleName -RecipientDomainIs $domain
            Write-Host "Protecting Domain $domain"
        }
            
        }
    }
    if ($SafeAttachmentsRule -eq $null) {
        $currentLoggedInUser = Read-Host "Please input the GA email"
        New-SafeAttachmentRule -name $SafeAttachmentsRuleName -SafeAttachmentPolicy $SafeAttachmentsRuleName -SentTo $currentLoggedInUser -Enabled $true
        
        
        foreach ($domain in $domains) {
            
            Set-SafeAttachmentRule -Identity $SafeAttachmentsRuleName -RecipientDomainIs $domain
            Write-Host "Protecting Domain $domain"
        }
    
    Write-Host "All Safe Attachment Rules Enabled!"
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
PhishingPolicy
SafeAttachmentsPolicy
SafeAttachmentsRule