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
            Write-Host "$property not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
            $param = @{ Identity = "Default" }
            $param.$property = "$message"
            Set-HostedContentFilterPolicy @param
        }
    }

    Write-Host "All Spam Settings Enabled!" -ForegroundColor Black -BackgroundColor Green
}
Function MalwarePolicy {
    #Malware Policy
    Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $true -QuarantineTag "SSSAus DefaultPolicy"

    Write-Host "All Malware Policies Enabled!" -ForegroundColor Black -BackgroundColor Green
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
                Write-Host "$PhishATPproperty not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
                $PhishATPparam = @{ Identity = "Office365 AntiPhish Default" }
                $PhishATPparam.$PhishATPproperty = $PhishATPmessage
                Set-AntiPhishPolicy @PhishATPparam
            }
        }
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -TargetedDomainsToProtect $domain
            Write-Host "Protecting Domain $domain" -ForegroundColor Black -BackgroundColor Yellow
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
                    Write-Host "$Phishproperty not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
                    $Phishparam = @{ Identity = "Office365 AntiPhish Default" }
                    $Phishparam.$Phishproperty = $Phishmessage
                    Set-AntiPhishPolicy @Phishparam
                }
            
    
        }
        
        Write-Host "All Phishing Settings Enabled!" -ForegroundColor Black -BackgroundColor Green
    }
    }
Function SafeAttachmentsPolicy {
    $SafeAttachmentsName = "$companyName "+"DefaultPolicy"
    $SafeAttachmentsPolicy = Get-SafeAttachmentPolicy | Where-Object {$_.Identity -like "*$SafeAttachmentsName*"}
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
                Write-Host "$SAproperty not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
                $SAparam = @{ Identity = "$SafeAttachmentsName" }
                $SAparam.$SAproperty = $SAmessage
                Set-SafeAttachmentPolicy @SAparam
            }
        }
    }
    if ($SafeAttachmentsPolicy -eq $null) {
        New-SafeAttachmentPolicy -Name $SafeLinksName -Action "DynamicDelivery" -ActionOnError $true -QuarantineTag "$QuarantineName" -Enable $true
    }
    Write-Host "All Safe Attachment Settings Enabled!" -ForegroundColor Black -BackgroundColor Green
}
Function SafeAttachmentsRule {
    $SafeAttachmentsRuleName = "$companyName "+"DefaultPolicy"
    $SafeAttachmentsRule = Get-SafeAttachmentRule | Where-Object {$_.Identity -like "*$SafeAttachmentsRuleName*"}

    if ($SafeAttachmentsRule -ne $null) {
        
        $SafeAttachmentsRulesettingsToCheck = @{
            SafeAttachmentPolicy = "$SafeAttachmentsName"

        }
        foreach ($SARsetting in $SafeAttachmentsRulesettingsToCheck.GetEnumerator()) {
            $SARproperty = $SARsetting.Key
            $SARmessage = $SARsetting.Value
            if ($SafeAttachmentseRule.$SARproperty -notmatch $SARmessage) {
                Write-Host "$SARproperty not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
                $SARparam = @{ Identity = "$SafeAttachmentsRuleName" }
                $SARparam.$SARproperty = $SARmessage
                Set-SafeAttachmentRule @SARparam
            }
        }
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            
            Set-SafeAttachmentRule -Identity $SafeAttachmentsRuleName -RecipientDomainIs $domain
            Write-Host "Protecting Domain $domain" -ForegroundColor Black -BackgroundColor Yellow
        }
            
        }
        if ($SafeAttachmentsRule -eq $null) {
            
            New-SafeAttachmentRule -name $SafeAttachmentsRuleName -SafeAttachmentPolicy $SafeAttachmentsRuleName -SentTo $currentLoggedInUser -Enabled $true
            
            
            foreach ($domain in $domains) {
                
                Set-SafeAttachmentRule -Identity $SafeAttachmentsRuleName -RecipientDomainIs $domain
                Write-Host "Protecting Domain $domain" -ForegroundColor Black -BackgroundColor Yellow
            }
        
        Write-Host "All Safe Attachment Rules Enabled!" -ForegroundColor Black -BackgroundColor Green
    }
    }
Function SafeLinksPolicy {
        $SafeLinksName = "$companyName "+"DefaultPolicy"
        $SafeLinksPolicy = Get-SafeLinksPolicy -Identity $SafeLinksName
        if ($SafeLinksPolicy -match $SafeLinksName) {
            $SafeLinkssettingsToCheck = @{
                AllowClickThrough = $false
                DeliverMessageAfterScan = $false
                EnableForInternalSenders = $true
                EnableSafeLinksForEmail = $true
                EnableSafeLinksForTeams = $true
                ScanUrls = $true
                TrackClicks = $true
            }
            foreach ($SLsetting in $SafeLinkssettingsToCheck.GetEnumerator()) {
                $SLproperty = $SLsetting.Key
                $SLmessage = $SLsetting.Value
                if ($SafeLinksPolicy.$SLproperty -notmatch $SLmessage) {
                    Write-Host "$SLproperty not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
                    $SLparam = @{ Identity = "$SafeLinksName" }
                    $SLparam.$SLproperty = $SLmessage
                    Set-SafeLinksPolicy @SLparam
                }
            }
        }
        if ($SafeLinksPolicy -notmatch $SafeLinksName) {
            New-SafeLinksPolicy -Name $SafeLinksName -AllowClickThrough $false -DeliverMessageAfterScan $false -EnableForInternalSenders $true -EnableSafeLinksForEmail $true -EnableSafeLinksForTeams $true -ScanUrls $true -TrackClicks $true -Enable $true
        }
        Write-Host "All Safe Links Settings Enabled!" -ForegroundColor Black -BackgroundColor Green
    }  

Function SafeLinksRule {
        $SafeLinksRuleName = "$companyName "+"DefaultPolicy"
        $SafeLinksRule = Get-SafeLinksRule -identity $SafeLinksRuleName
        
    
        if ($SafeLinksRule -match $SafeLinksRuleName) {
            
            $SafeLinksRulesettingsToCheck = @{
                SafeLinksPolicy = "$SafeLinksName"
    
            }
            foreach ($SLRsetting in $SafeLinksRulesettingsToCheck.GetEnumerator()) {
                $SLRproperty = $SLRsetting.Key
                $SLRmessage = $SLRsetting.Value
                if ($SafeLinksRule.$SLRproperty -notmatch $SLRmessage) {
                    Write-Host "$SARproperty not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
                    $SLRparam = @{ Identity = "$SafeLinksRuleName" }
                    $SLRparam.$SLRproperty = $SLRmessage
                    Set-SafeLinksRule @SLRparam
                }
            }
            $domains = Get-AcceptedDomain
            foreach ($domain in $domains) {
                
                Set-SafeLinksRule -Identity $SafeLinksRuleName -RecipientDomainIs $domain
                Write-Host "Protecting Domain $domain" -ForegroundColor Black -BackgroundColor Yellow
            }
                
            }
            if ($SafeLinksRule -notmatch $SafeLinksRuleName) {
                
                New-SafeLinksRule -name $SafeLinksRuleName -SafeLinksPolicy $SafeLinksRuleName -SentTo $currentLoggedInUser -Enabled $true
                
                
                foreach ($domain in $domains) {
                    
                    Set-SafeLinksRule -Identity $SafeLinksRuleName -RecipientDomainIs $domain
                    Write-Host "Protecting Domain $domain" -ForegroundColor Black -BackgroundColor Yellow
                }
            
            Write-Host "All Safe Links Rules Enabled!" -ForegroundColor Black -BackgroundColor Green
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

Function SetSecurityPolicies {
    Process {
        QuaratinePolicy
        SpamPolicy
        MalwarePolicy
        PhishingPolicy
        SafeAttachmentsPolicy
        SafeAttachmentsRule
        SafeLinksPolicy
        SafeLinksRule
    }
}

Write-Host "What is the Companys Name? (Keep Name as a Whole Word, No Spaces)" -ForegroundColor Black -BackgroundColor Yellow
$companyName = Read-Host "Name:"
$currentLoggedInUser = Read-Host "Please input the GA email"
#Runs Tests and Checks
SetSecurityPolicies