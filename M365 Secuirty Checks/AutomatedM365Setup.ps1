
Write-Host "What is the Companys Name? (Keep Name as a Whole Word, No Spaces)" -ForegroundColor Black -BackgroundColor Yellow
$companyName = Read-Host "Name:"
Write-Host "What is the Global Admins Email?" -ForegroundColor Black -BackgroundColor Yellow
$currentLoggedInUser = Read-Host "Please input the GA email"
Write-Host "Whats is the Clients IP Address, use the Subnet /32" --ForegroundColor Black -BackgroundColor Yellow
$CompanyIP = Read-Host "IP"
Write-Host "What is the MSP IP you are working from? Use the Subnet /32" -ForegroundColor Black -BackgroundColor Yellow
$MSPIP = Read-Host "IP"
Write-Host "Does the Tenant have access to AAD P1 or P2? `n If the Tenant has access to Business Premium or above then likely Yes" -ForegroundColor Black -BackgroundColor Yellow
$AADCheck = Read-Host "Y/N"
Write-Host "Does the Tenant has access to Defender for O365 P1 or P2? `n If the Tenant has access to Business Premium or above then likely Yes" -ForegroundColor Black -BackgroundColor Yellow
$DefenderCheck = Read-Host "Y/N"

$SafeLinksRuleName = "$companyName "+"DefaultPolicy"
$SafeAttachmentsName = "$companyName "+"DefaultPolicy"
$SafeAttachmentsRuleName = "$companyName "+"DefaultPolicy"
$QuarantineName = "$companyName "+"DefaultPolicy"
$SafeLinksName = "$companyName "+"DefaultPolicy"
$MSPOffice = "MSP Offices"
$CompanyNameLocationName = "$companyName Office"
$TrustedCountriesLocationName = "$companyName Office"





#Function to connect to Mg graph
Function ConnectTo-MgGraph {
# Check if MS Graph module is installed
if (-not(Get-InstalledModule Microsoft.Graph)) { 
    Write-Host "Microsoft Graph module not found" -ForegroundColor Black -BackgroundColor Yellow
    $install = Read-Host "Do you want to install the Microsoft Graph Module?"

    if ($install -match "[yY]") {
        Install-Module Microsoft.Graph -Repository PSGallery -Scope CurrentUser -AllowClobber -Force
    }
    else {
        Write-Host "Microsoft Graph module is required." -ForegroundColor Black -BackgroundColor Yellow
        exit
    } 
}

# Connect to Graph
Write-Host "Connecting to Microsoft Graph" -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.Read.All, UserAuthenticationMethod.Read.All, Directory.Read.All, Group.Read.All, IdentityProvider.Read.All, Policy.Read.All, Policy.ReadWrite.ConditionalAccess, Directory.AccessAsUser.All"

# Select the beta profile
Select-MgProfile Beta
}

#Function to connect to EXO
Function ConnectTo-EXO {
# Check if Exo module is installed
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

# Connect to EXO
Write-Host "Connecting to Microsoft EXO" -ForegroundColor Cyan
Connect-exchangeonline
}

#Fucntion to connect to MS online
Function ConnectTo-MSOL {
# Check if MS Online module is installed
if (-not(Get-InstalledModule MSOnline)) { 
    Write-Host "Microsoft Online module not found" -ForegroundColor Black -BackgroundColor Yellow
    $install = Read-Host "Do you want to install the Microsoft Online Module?"

    if ($install -match "[yY]") {
        Install-Module MSOnline -Repository PSGallery -Scope CurrentUser -AllowClobber -Force
    }
    else {
        Write-Host "Microsoft Online module is required." -ForegroundColor Black -BackgroundColor Yellow
        exit
    } 
}

# Connect to Graph
Write-Host "Connecting to Microsoft Online " -ForegroundColor Cyan
Connect-MsolService
}

#Function to disconnect sessions after use
Function DisconnectSessions {
Write-host "DISCONNECTING PERVIOUS SESSIONS" -ForegroundColor Black -BackgroundColor Red
#Disconnect From Services
Disconnect-ExchangeOnline
Disconnect-MgGraph
}

#Function to create the Quarantine Policy
Function QuaratinePolicy {

try {
$QuarantinePolicy = Get-QuarantinePolicy -Identity $QuarantineName
New-QuarantinePolicy -Name $QuarantineName -EndUserQuarantinePermissionsValue 63 -ESNEnabled $true


Write-Host "Quarantine Policy $QuarantineName has been created" -ForegroundColor Black -BackgroundColor Green

}
catch {
    Write-Host "Error occurred Setting Quarantine Policy"
    Write-Host $_.Exception.Message
}
}

Function SpamPolicy {
#Specifies the Command to use for Checking
$SpamPolicy = Get-HostedContentFilterPolicy -Identity "Default"
#Specifies the settings and Values that needto be set
$SpamsettingsToCheck = @{
    MarkAsSpamNdrBackscatter = "On"
    MarkAsSpamSpfRecordHardFail = "On"
    MarkAsSpamFromAddressAuthFail = "On"
    SpamQuarantineTag = $QuarantineName
    HighConfidenceSpamQuarantineTag = $QuarantineName
    PhishQuarantineTag = $QuarantineName
    HighConfidencePhishQuarantineTag = $QuarantineName
    BulkQuarantineTag = $QuarantineName
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
Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $true -QuarantineTag $QuarantineName

Write-Host "All Malware Policies Enabled!" -ForegroundColor Black -BackgroundColor Green
}
Function PhishingPolicy {
$PhishingPolicy = Get-AntiPhishPolicy -Identity "Office365 AntiPhish Default"
# $accountSKU = Get-MsolAccountSku | Where-Object {$_.AccountSkuId -like "*ATP_ENTERPRISE*"}
# $accountSKU = $true



if($DefenderCheck -match "[yY]"){
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
        MailboxIntelligenceQuarantineTag = $QuarantineName
        SpoofQuarantineTag = $QuarantineName
        TargetedDomainProtectionAction = "Quarantine"
        TargetedDomainQuarantineTag = $QuarantineName
        TargetedUserProtectionAction = "Quarantine"
        TargetedUserQuarantineTag = $QuarantineName

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
    if($DefenderCheck -match "[nN]"){
    
        $PhishsettingsToCheck = @{
            EnableSpoofIntelligence = $true
            EnableFirstContactSafetyTips = $true
            EnableViaTag = $true
            EnableUnauthenticatedSender = $true
            AuthenticationFailAction = "Quarantine"
            DmarcRejectAction = "Quarantine"
            DmarcQuarantineAction = "Quarantine"
            SpoofQuarantineTag = $QuarantineName
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
if($DefenderCheck -match "[yY]") {
$SafeAttachmentsPolicy = Get-SafeAttachmentPolicy | Where-Object {$_.Identity -like "*$SafeAttachmentsName*"}
if ($SafeAttachmentsPolicy -ne $null) {
    $SafeAttachmentssettingsToCheck = @{
        Action = "DynamicDelivery"
        ActionOnError = $true
        QuarantineTag = $QuarantineName
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
    New-SafeAttachmentPolicy -Name $SafeAttachmentsName -Action "DynamicDelivery" -ActionOnError $true -QuarantineTag $QuarantineName -Enable $true
}
Write-Host "All Safe Attachment Settings Enabled!" -ForegroundColor Black -BackgroundColor Green
}
}
Function SafeAttachmentsRule {
if ($DefenderCheck -match "[yY]") {
$SafeAttachmentsRule = Get-SafeAttachmentRule -Identity $SafeAttachmentsRuleName

if ($SafeAttachmentsRule -ne $null) {
    
    $SafeAttachmentsRulesettingsToCheck = @{
        SafeAttachmentPolicy = $SafeAttachmentsName

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
}
Function SafeLinksPolicy {
if ($DefenderCheck -match "[yY]") {
    $SafeLinksPolicy = Get-SafeLinksPolicy -Identity $SafeLinksName
    if ($SafeLinksPolicy -ne $null) {
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
                $SLparam = @{ Identity = $SafeLinksName }
                $SLparam.$SLproperty = $SLmessage
                Set-SafeLinksPolicy @SLparam
            }
        }
    }
    if ($SafeLinksPolicy -eq $null) {
        
        New-SafeLinksPolicy -Name $SafeLinksName -AllowClickThrough $false -DeliverMessageAfterScan $false -EnableForInternalSenders $true -EnableSafeLinksForEmail $true -EnableSafeLinksForTeams $true -ScanUrls $true -TrackClicks $true
    }
    Write-Host "All Safe Links Settings Enabled!" -ForegroundColor Black -BackgroundColor Green
}
}  
Function SafeLinksRule {
if($DefenderCheck -match "[yY]") {  
    $SafeLinksRule = Get-SafeLinksRule -identity $SafeLinksRuleName
    

    if ($SafeLinksRule -ne $null) {
        
        $SafeLinksRulesettingsToCheck = @{
            SafeLinksPolicy = $SafeLinksName

        }
        foreach ($SLRsetting in $SafeLinksRulesettingsToCheck.GetEnumerator()) {
            $SLRproperty = $SLRsetting.Key
            $SLRmessage = $SLRsetting.Value
            if ($SafeLinksRule.$SLRproperty -notmatch $SLRmessage) {
                Write-Host "$SARproperty not enabled, Enabling now...." -ForegroundColor Black -BackgroundColor Yellow
                $SLRparam = @{ Identity = $SafeLinksRuleName }
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
        if ($SafeLinksRule -eq $null) {
            
            New-SafeLinksRule -name $SafeLinksRuleName -SafeLinksPolicy $SafeLinksRuleName -SentTo $currentLoggedInUser
            
            
            foreach ($domain in $domains) {
                
                Set-SafeLinksRule -Identity $SafeLinksRuleName -RecipientDomainIs $domain
                Write-Host "Protecting Domain $domain" -ForegroundColor Black -BackgroundColor Yellow
            }
        
        Write-Host "All Safe Links Rules Enabled!" -ForegroundColor Black -BackgroundColor Green
    }
    }
}

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

#Fuction to enabled CA or Security Defaults
Function IdentityProtection {


    try {
        #Sets the MSP Offlice Location Name
        $MSPNamedLocationName = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$MSPOffice'" | Select-Object -expandproperty Id
        }
        catch {
            Write-Host "Error occurred for Named Location: $MSPNamedLocationName"
            Write-Host $_.Exception.Message
        }
        try {
        #Sets the Companys Location Name
        $OfficeNameLocationName = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$CompanyNameLocationName'" | Select-Object -expandproperty Id
        }
        catch {
            Write-Host "Error occurred for Named Location: $OfficeNameLocationName"
            Write-Host $_.Exception.Message
        }
        try {
        #Sets the Trusted Location Name
        $TrustedLocationName = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$TrustedCountriesLocationName'" | Select-Object -expandproperty Id
        }
        catch {
            Write-Host "Error occurred for Named Location: $TrustedLocationName"
            Write-Host $_.Exception.Message
        }


    #Sets the MSP IP Locations Params for Named Locations
    $MSPIPLocationparams = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        DisplayName = "MSP Offices"
        IsTrusted = $true
        IpRanges = @(
            @{
                "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                CidrAddress = "$MSPIP"
                
            }
            
            
        )
    }


    #Sets the Client IP Locations Params for Named Locations
    $CompanyIPLocationparams = @{
    "@odata.type" = "#microsoft.graph.ipNamedLocation"
    DisplayName = $CompanyNameLocationName
    IsTrusted = $true
    IpRanges = @(
    @{
        "@odata.type" = "#microsoft.graph.iPv4CidrRange"
        CidrAddress = "$CompanyIP"
    }

    )
    }

    #Sets the Trusted Countries Param for Named Locations
    $TrustedCountryParams = @{
        "@odata.type" = "#microsoft.graph.countryNamedLocation"
        DisplayName = "Trusted Countries"
        CountriesAndRegions = @(
            "AU"
        )
        IncludeUnknownCountriesAndRegions = $false

    }



    #Checks if the MSP Location Already Exists
    if($MSPNamedLocationName -eq $null){
        New-MgIdentityConditionalAccessNamedLocation -BodyParameter $MSPIPLocationparams
    }

    #Checks if the Client Location Already Exists
    if($OfficeNameLocationName -eq $null){
        New-MgIdentityConditionalAccessNamedLocation -BodyParameter $CompanyIPLocationparams
    }

    #Checks if the Trausted Countries Already Exists
    If($TrustedLocationName -eq $null){
        New-MgIdentityConditionalAccessNamedLocation -BodyParameter $TrustedCountryParams
    }



    #Checks if the CA excluded group exists and created it if not, then reassigns the new value if needed
    $CAExcludedGroupIDCheck = Get-MGgroup -Filter "DisplayName eq 'Security- CA Exclude from all Policies'" | Select-object -expandproperty Id
    if($CAExcludedGroupIDCheck -eq $null){
    New-MgGroup -DisplayName 'Security- CA Exclude from all Policies' -MailNickName 'securitycaexcludefromallpolicies' -MailEnabled:$False -SecurityEnabled
    }
    $CAExcludedGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- CA Exclude from all Policies'" | Select-object -expandproperty Id



    #Checks if the GA Admins for CA exists and created it if not, then reassigns the new value if needed
    $CAGAOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- GA Admins for CA'" | Select-object -expandproperty Id
    if($CAGAOnlyGroupID -eq $null){
    New-MgGroup -DisplayName 'Security- GA Admins for CA' -MailNickName 'securitygaadminsforca' -MailEnabled:$False -SecurityEnabled
    }
    $CAGAOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- GA Admins for CA'" | Select-object -expandproperty Id


    
    #Checks if the Service Accounts for CA exists and created it if not, then reassigns the new value if needed
    $ServiceOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- Exclude Service Accounts'" | Select-object -expandproperty Id
    if($ServiceOnlyGroupID -eq $null){
    New-MgGroup -DisplayName 'Security- Exclude Service Accounts' -MailNickName 'securityexcludeserviceaccounts' -MailEnabled:$False -SecurityEnabled
    }
    $ServiceOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- Exclude Service Accounts'" | Select-object -expandproperty Id

    #Checks if the International User for CA exists and created it if not, then reassigns the new value if needed
    $InternationalUserOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- International User'" | Select-object -expandproperty Id
    if($InternationalUserOnlyGroupID -eq $null){
    New-MgGroup -DisplayName 'Security- International User' -MailNickName 'securityinternationaluser' -MailEnabled:$False -SecurityEnabled
    }
    $InternationalUserOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- International User'" | Select-object -expandproperty Id


    #Checks if the Travelling User for CA exists and created it if not, then reassigns the new value if needed
    $TravellingUserOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- Travelling User'" | Select-object -expandproperty Id
    if($TravellingUserOnlyGroupID -eq $null){
    New-MgGroup -DisplayName 'Security- Travelling User' -MailNickName 'securitytravellinguser' -MailEnabled:$False -SecurityEnabled
    }
    $TravellingUserOnlyGroupID = Get-MGgroup -Filter "DisplayName eq 'Security- Travelling User'" | Select-object -expandproperty Id


    #Sets the Params for the Coditional access policies
    $CAParams =@(
        #Admins | All Cloud Apps | IdentityProtection: Enforce Azure MFA on Directory Roles
        @{
            DisplayName = "Admins | All Cloud Apps | IdentityProtection: Enforce Azure MFA on Directory Roles"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "mobileAppsAndDesktopClients"
                    "browser"

                )
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Users = @{
                    ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    )
                    
                    IncludeRoles = @(
                        #Global Admin
                        "fdd7a751-b60b-444a-984c-02652fe8fa1c"
                        #User Admin
                        "fe930be7-5e62-47db-91af-98c3a49a38b1"
                        #Conditional Access Admin
                        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
                        #Authentication Admin
                        "c4e39bd9-1100-46d3-8c65-fb160da0071f"
                        #PIM Role Admin
                        "e8611ab8-c189-46e8-94e1-60213ab1f814"




                )
            }
                
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "mfa"
                )
            }
            SessionControls = @{
                PersistentBrowser = @{
                    isEnabled = $true
                    Mode = "never"
                }
                
            }
        }
        #Admins | All Cloud Apps | Require MFA ALL Admin Roles
        @{  
            DisplayName = "Admins | All Cloud Apps | Require MFA ALL Admin Roles"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Users = @{
                    ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    )
                    IncludeRoles = @(
                        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
                        "c430b396-e693-46cc-96f3-db01bf8bb62a"
                        "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d"
                        "8424c6f0-a189-499e-bbd0-26c1753c96d4"
                        "25a516ed-2fa0-40ea-a2d0-12923a21473a"
                        "c4e39bd9-1100-46d3-8c65-fb160da0071f"
                        "0526716b-113d-4c15-b2c8-68e3c22b9f80"
                        "9f06204d-73c1-4d4c-880a-6edb90606fd8"
                        "e3973bdf-4987-49ae-837a-ba8e231c7286"
                        "7495fdc4-34c4-4d15-a289-98788ce399fd"
                        "aaf43236-0c0d-4d5f-883a-6955382ac081"
                        "3edaf663-341e-4475-9f94-5c398ef6c070"
                        "b0f54661-2d74-4c50-afa3-1ec803f12efe"
                        "158c047a-c907-4556-b7ef-446551a6b5f7"
                        "892c5842-a9a6-463a-8041-72aa08ca3cf6"
                        "7698a772-787b-4ac8-901f-60d6b08affd2"
                        "17315797-102d-40b4-93e0-432062caca18"
                        "e6d1a23a-da11-4be4-9570-befc86d067a7"
                        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
                        "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4"
                        "8329153b-31d0-4727-b945-745eb3bc5f31"
                        "44367163-eba1-44c3-98af-f5787879f96a"
                        "3f1acade-1e04-4fbc-9b69-f0302cd84aef"
                        "29232cdf-9323-42fd-ade2-1d097af3e4de"
                        "31392ffb-586c-42d1-9346-e59415a2cc4e"
                        "6e591065-9bad-43ed-90f3-e9424366d2f0"
                        "0f971eea-41eb-4569-a71e-57bb8a3eff1e"
                        "be2f45a1-457d-42af-a067-6ec1fa63bc45"
                        "62e90394-69f5-4237-9190-012177145e10"
                        "fdd7a751-b60b-444a-984c-02652fe8fa1c"
                        "729827e3-9c14-49f7-bb1b-9608f156bbb8"
                        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"
                        "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e"
                        "eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c"
                        "3a2c62db-5318-420d-8d74-23affee5d9d5"
                        "74ef975b-6605-40af-a5d2-b9539d836353"
                        "b5a8dcf3-09d5-43a9-a639-8e29ef291470"
                        "4d6ac14f-3453-41d0-bef9-a3e0c569773a"
                        "59d46f88-662b-457b-bceb-5c3809e5908f"
                        "1501b917-7653-4ff9-a4b5-203eaf33784f"
                        "d37c8bed-0711-4417-ba38-b4abe66ce4c2"
                        "2b745bdf-0803-4d80-aa65-822c4493daac"
                        "966707d0-3269-4727-9be2-8c3a10f19b9d"
                        "af78dc32-cf4d-46f9-ba4e-4428526346b5"
                        "a9ea8996-122f-4c74-9520-8edcd192826c"
                        "11648597-926c-4cf3-9c36-bcebb0ba8dcc"
                        "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f"
                        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
                        "e8611ab8-c189-46e8-94e1-60213ab1f814"
                        "0964bb5e-9bdb-4d7b-ac29-58e794862a40"
                        "194ae4cb-b126-40b2-bd5b-6091b380977d"
                        "f023fd81-a637-4b56-95fd-791ac0226033"
                        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
                        "75941009-915a-4869-abe7-691bff18279e"
                        "69091246-20e8-4a56-aa4d-066075b2a7a8"
                        "baf37b3a-610e-45da-9e62-d9d1e5e8914b"
                        "3d762c5a-1b6c-493f-843e-55a3b42923d4"
                        "fe930be7-5e62-47db-91af-98c3a49a38b1"
                        "e300d9e7-4a2b-4295-9eff-f1c78b36cc98"
                        "92b086b3-e367-4ef2-b869-1de128fb986e"
                        "11451d60-acb2-45eb-a7d6-43d0f0125c13"
                        "32696413-001a-46ae-978c-ce0f6b3620d2"
                        "810a2642-a034-447f-a5e8-41beaa378541"
                        

                )
            }
                
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "mfa"
                )
            }
            SessionControls = @{
                PersistentBrowser = @{
                    isEnabled = $true
                    Mode = "never"
                }
                
            }
        }
        #GlobalAdmins | All Cloud Apps | AttackSurfaceReduction: Block Non-Named IPs
        @{  
            DisplayName = "GlobalAdmins | All Cloud Apps | AttackSurfaceReduction: Block Non-Named IPs"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "mobileAppsAndDesktopClients"
                    "browser"
                )
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Locations = @{
                    IncludeLocations = @(
                        "All"
                    )
                    ExcludeLocations = @(
                        "$MSPNamedLocationName"
                        "$OfficeNameLocationName"
                    )
                }
                Users = @{
                IncludeGroups = @(
                    "$CAGAOnlyGroupID"
                )
                ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    )
                }
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "block"
                )
            }
            SessionControls = @{
                PersistentBrowser = @{
                    isEnabled = $true
                    Mode = "never"
                }
                
            }
        }
        #AllUsers | All Cloud Apps | AttackSurfaceReduction: Block International Login Attempts
        @{  
            DisplayName = "AllUsers | All Cloud Apps | AttackSurfaceReduction: Block International Login Attempts"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "mobileAppsAndDesktopClients"
                    "browser"
                )
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Locations = @{
                    IncludeLocations = @(
                        "All"
                    )
                    ExcludeLocations = @(
                        "$TrustedLocationName"
                        "$InternationalUserOnlyGroupID"
                        "$TravellingUserOnlyGroupID"
                    )
                }
                Users = @{
                IncludeUsers = @(
                        "All"
                )
                ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    ) 
                }
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "block"
                )
            }
        }
        #AllUsers | All Cloud Apps | AuthProtocols: Block Legacy Authentication Protocols
        @{  
            DisplayName = "AllUsers | All Cloud Apps | AuthProtocols: Block Legacy Authentication Protocols"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "ExchangeActiveSync"
                    "Other"
                )
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Users = @{
                IncludeUsers = @(
                        "All"
                )
                ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    )
                }
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "block"
                )
            }
        }
        #AllUsers | All Cloud Apps | IdentityProtection: Enforce Azure MFA
        @{  
            DisplayName = "AllUsers | All Cloud Apps | IdentityProtection: Enforce Azure MFA"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "mobileAppsAndDesktopClients"
                    "browser"
                )
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Users = @{
                IncludeUsers = @(
                        "All"
                )
                ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    )
                }
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "mfa"
                )
            }
        }
        #Guests | All Cloud Apps | DataProtection: Prevents Persistent Browser Sessions for Guest Users
        @{  
            DisplayName = "Guests | All Cloud Apps | DataProtection: Prevents Persistent Browser Sessions for Guest Users"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "browser"
                )
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Users = @{
                    IncludeUsers = @(
                        "GuestsOrExternalUsers"
                    )
                    ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    )
                }
            
            }
            SessionControls = @{
                PersistentBrowser = @{
                    isEnabled = $true
                    Mode = "never"
                }
                
            }
        }
        #Guests | All Cloud Apps | IdentityProtection: Require MFA for guests
        @{  
            DisplayName = "Guests | All Cloud Apps | IdentityProtection: Require MFA for guests"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "mobileAppsAndDesktopClients"
                    "browser"
                )
                Applications = @{
                    includeApplications = @(
                        'All'
                    )
                }
                Users = @{
                    IncludeUsers = @(
                        "GuestsOrExternalUsers"
                    )
                    ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        "$ServiceOnlyGroupID"
                    )
                }
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "block"
                )
            }
            
        }
        #ServiceAccounts | All Cloud Apps | AttackSurfaceReduction: Restrict Service Accounts
        @{  
            DisplayName = "ServiceAccounts | All Cloud Apps | AttackSurfaceReduction: Restrict Service Accounts"
            State = "EnabledForReportingButNotEnforced"
            Conditions = @{
                ClientAppTypes = @(
                    "mobileAppsAndDesktopClients"
                    "browser"
                    "ExchangeActiveSync"
                    "Other"
                )
                Applications = @{
                    includeApplications = @(
                        'None'
                    )
                }
                Users = @{
                    IncludeUsers = @(
                        "$ServiceOnlyGroupID"
                    )
                    ExcludeGroups = @(
                        "$CAExcludedGroupID"
                        
                    )
                }
                Locations = @{
                    IncludeLocations = @(
                        "All"
                    )
                    ExcludeLocations = @(
                        "$TrustedLocationName"
                        "$MSPNamedLocationName"
                        "$OfficeNameLocationName"
                    )
                }
            
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @(
                    "block"
                )
            }
            
        }
        
    )


    #If AAD_PREMIUM Exists
    if ($AADCheck -match "[yY]"){

        # Iterate over each object in CAParams
            foreach ($policyParams in $CAParams) {
                $CAName = $policyParams.DisplayName
                $CACheck = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$CAName'" | Select-Object -ExpandProperty Id
                
                if($CACheck -eq $null){
                New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                }
                
                if($CACheck -ne $null){
                    Write-Host "CA Policy $CAName Already Exists" -ForegroundColor Black -BackgroundColor Yellow
                }
            }
        }
        
        #If AAD_PREMIUM Doesnt Exist
        if ($AADCheck -match "[nN]"){
            $SecurityDefaultsparams = @{
                IsEnabled = $false
            }
            Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $SecurityDefaultsparams
        }
        
        Write-Host "Identity Protection Complete" -ForegroundColor Black -BackgroundColor Yellow


}

ConnectTo-MSOL
ConnectTo-EXO
ConnectTo-MgGraph

#Runs Tests and Checks

SetSecurityPolicies
IdentityProtection
DisconnectSessions