[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    [Parameter(
        Mandatory = $false,
        ParameterSetName = "UserPrincipalName",
        HelpMessage = "Enter a single UserPrincipalName or a comma separted list of UserPrincipalNames",
        Position = 0
    )]
    [string[]]$UserPrincipalName,

    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $false,
        ParameterSetName = "AdminsOnly"
    )]
    # Get only the users that are an admin
    [switch]$adminsOnly = $false,

    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $false,
        ParameterSetName = "Licensed"
    )]
    # Check only the MFA status of users that have license
    [switch]$IsLicensed = $false,

    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = "withOutMFAOnly"
    )]
    # Get only the users that don't have MFA enabled
    [switch]$withOutMFAOnly = $false,

    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $false
    )]
    # Check if a user is an admin. Set to $false to skip the check
    [switch]$listAdmins = $true,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Enter path to save the CSV file"
    )]
    [string]$path = ".\$p-MFAStatus-$((Get-Date -format "MMM-dd-yyyy").ToString()).csv"
)

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
    Connect-MgGraph -Scopes "User.Read.All, UserAuthenticationMethod.Read.All, Directory.Read.All, Group.Read.All, IdentityProvider.Read.All, Policy.Read.All"

    # Select the beta profile
    Select-MgProfile Beta
}
Function ConnectTo-EXO {
    # Check if MS Graph module is installed
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

    # Connect to Graph
    Write-Host "Connecting to Microsoft EXO" -ForegroundColor Cyan
    Connect-exchangeonline
}
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

Function Get-Admins {
    <#
  .SYNOPSIS
    Get all user with an Admin role
  #>
    process {
        $admins = Get-MgDirectoryRole | Select-Object DisplayName, Id | 
        % { $role = $_.displayName; Get-MgDirectoryRoleMember -DirectoryRoleId $_.id | 
            where { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user" } | 
            % { Get-MgUser -userid $_.id | Where-Object { ($_.AssignedLicenses).count -gt 0 } }
        } | 
        Select @{Name = "Role"; Expression = { $role } }, DisplayName, UserPrincipalName, Mail, ObjectId | Sort-Object -Property Mail -Unique
    
        return $admins
    }
}

Function Get-Users {
    <#
  .SYNOPSIS
    Get users from the requested DN
  #>
    process {
        # Set the properties to retrieve
        $select = @(
            'id',
            'DisplayName',
            'userprincipalname',
            'mail'
        )

        $properties = $select + "AssignedLicenses"

        # Get enabled, disabled or both users
        switch ($enabled) {
            "true" { $filter = "AccountEnabled eq true and UserType eq 'member'" }
            "false" { $filter = "AccountEnabled eq false and UserType eq 'member'" }
            "both" { $filter = "UserType eq 'member'" }
        }
    
        # Check if UserPrincipalName(s) are given
        if ($UserPrincipalName) {
            Write-host "Get users by name" -ForegroundColor Cyan

            $users = @()
            foreach ($user in $UserPrincipalName) {
                try {
                    $users += Get-MgUser -UserId $user -Property $properties | select $select -ErrorAction Stop
                }
                catch {
                    [PSCustomObject]@{
                        DisplayName       = " - Not found"
                        UserPrincipalName = $User
                        isAdmin           = $null
                        MFAEnabled        = $null
                    }
                }
            }
        }
        elseif ($adminsOnly) {
            Write-host "Get admins only" -ForegroundColor Cyan

            $users = @()
            foreach ($admin in $admins) {
                $users += Get-MgUser -UserId $admin.UserPrincipalName -Property $properties | select $select
            }
        }
        else {
            if ($IsLicensed) {
                # Get only licensed users
                $users = Get-MgUser -Filter $filter -Property $properties -all | Where-Object { ($_.AssignedLicenses).count -gt 0 } | select $select
            }
            else {
                $users = Get-MgUser -Filter $filter -Property $properties -all | select $select
            }
        }
        return $users
    }
}

Function Get-MFAMethods {
    <#
    .SYNOPSIS
      Get the MFA status of the user
  #>
    param(
        [Parameter(Mandatory = $true)] $userId
    )
    process {
        # Get MFA details for each user
        [array]$mfaData = Get-MgUserAuthenticationMethod -UserId $userId

        # Create MFA details object
        $mfaMethods = [PSCustomObject][Ordered]@{
            status           = "-"
            authApp          = "-"
            phoneAuth        = "-"
            fido             = "-"
            helloForBusiness = "-"
            emailAuth        = "-"
            tempPass         = "-"
            passwordLess     = "-"
            softwareAuth     = "-"
            authDevice       = "-"
            authPhoneNr      = "-"
            SSPREmail        = "-"
        }

        ForEach ($method in $mfaData) {
            Switch ($method.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { 
                    # Microsoft Authenticator App
                    $mfaMethods.authApp = $true
                    $mfaMethods.authDevice = $method.AdditionalProperties["displayName"] 
                    $mfaMethods.status = "enabled"
                } 
                "#microsoft.graph.phoneAuthenticationMethod" { 
                    # Phone authentication
                    $mfaMethods.phoneAuth = $true
                    $mfaMethods.authPhoneNr = $method.AdditionalProperties["phoneType", "phoneNumber"] -join ' '
                    $mfaMethods.status = "enabled"
                } 
                "#microsoft.graph.fido2AuthenticationMethod" { 
                    # FIDO2 key
                    $mfaMethods.fido = $true
                    $fifoDetails = $method.AdditionalProperties["model"]
                    $mfaMethods.status = "enabled"
                } 
                "#microsoft.graph.passwordAuthenticationMethod" { 
                    # Password
                    # When only the password is set, then MFA is disabled.
                    if ($mfaMethods.status -ne "enabled") { $mfaMethods.status = "disabled" }
                }
                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { 
                    # Windows Hello
                    $mfaMethods.helloForBusiness = $true
                    $helloForBusinessDetails = $method.AdditionalProperties["displayName"]
                    $mfaMethods.status = "enabled"
                } 
                "#microsoft.graph.emailAuthenticationMethod" { 
                    # Email Authentication
                    $mfaMethods.emailAuth = $true
                    $mfaMethods.SSPREmail = $method.AdditionalProperties["emailAddress"] 
                    $mfaMethods.status = "enabled"
                }               
                "microsoft.graph.temporaryAccessPassAuthenticationMethod" { 
                    # Temporary Access pass
                    $mfaMethods.tempPass = $true
                    $tempPassDetails = $method.AdditionalProperties["lifetimeInMinutes"]
                    $mfaMethods.status = "enabled"
                }
                "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" { 
                    # Passwordless
                    $mfaMethods.passwordLess = $true
                    $passwordLessDetails = $method.AdditionalProperties["displayName"]
                    $mfaMethods.status = "enabled"
                }
                "#microsoft.graph.softwareOathAuthenticationMethod" { 
                    # ThirdPartyAuthenticator
                    $mfaMethods.softwareAuth = $true
                    $mfaMethods.status = "enabled"
                }
            }
        }
        Return $mfaMethods
    }
}

Function Get-MFAStatusUsers {
    <#
    .SYNOPSIS
      Get all AD users
  #>
    process {
        Write-Host "Collecting users" -ForegroundColor Cyan
    
        # Collect users
        $users = Get-Users
    
        Write-Host "Processing" $users.count "users" -ForegroundColor Cyan
        $UserNo = 1
        # Collect and loop through all users
        $users | ForEach {
      
            $mfaMethods = Get-MFAMethods -userId $_.id

            if ($withOutMFAOnly) {
                if ($mfaMethods.status -eq "disabled") {
                    [PSCustomObject]@{
                        "Name"            = $_.DisplayName
                        Emailaddress      = $_.mail
                        UserPrincipalName = $_.UserPrincipalName
                        isAdmin           = if ($listAdmins -and ($admins.UserPrincipalName -match $_.UserPrincipalName)) { $true } else { "-" }
                        MFAEnabled        = $false
                        "Phone number"    = $mfaMethods.authPhoneNr
                        "Email for SSPR"  = $mfaMethods.SSPREmail
                    }
                }
            }
            else {
                [pscustomobject]@{
                    "Name"                  = $_.DisplayName
                    Emailaddress            = $_.mail
                    UserPrincipalName       = $_.UserPrincipalName
                    isAdmin                 = if ($listAdmins -and ($admins.UserPrincipalName -match $_.UserPrincipalName)) { $true } else { "-" }
                    "MFA Status"            = $mfaMethods.status
                    # "MFA Default type" = ""  - Not yet supported by MgGraph
                    "Phone Authentication"  = $mfaMethods.phoneAuth
                    "Authenticator App"     = $mfaMethods.authApp
                    "Passwordless"          = $mfaMethods.passwordLess
                    "Hello for Business"    = $mfaMethods.helloForBusiness
                    "FIDO2 Security Key"    = $mfaMethods.fido
                    "Temporary Access Pass" = $mfaMethods.tempPass
                    "Authenticator device"  = $mfaMethods.authDevice
                    "Phone number"          = $mfaMethods.authPhoneNr
                    "Email for SSPR"        = $mfaMethods.SSPREmail
                }
            }
            
            
            Write-Progress -Activity "Processing Users" -Status "User Number $UserNo" -PercentComplete ($UserNo / $users.count * 100)
            Start-Sleep -Milliseconds 50
            $UserNo++
        }
    }
}

Function ConnectSessions {
Write-host "CONNECTING TO SESSIONS" -ForegroundColor Black -BackgroundColor Green
# Connect to Graph
ConnectTo-MgGraph

#Connect to EXO
ConnectTo-EXO

#Connect to DMARC
ConnectTo-DMARC
}
Function DisconnectSessions {
Write-host "DISCONNECTING PERVIOUS SESSIONS" -ForegroundColor Black -BackgroundColor Red
#Disconnect From Services
Disconnect-ExchangeOnline
Disconnect-MgGraph
}
Function MFAReport {
    mkdir C:\MHC
    Set-Location C:\MHC
    
    $Dir = Read-Host "Company Name?"
        mkdir $Dir
        Set-Location $dir
        $admins = $null
    
        if (($listAdmins) -or ($adminsOnly)) {
        $admins = Get-Admins
        } 
    
        $p = Get-AcceptedDomain
    
        # Get MFA Status
        Get-MFAStatusUsers | Sort-Object Name | Export-CSV -Path $path -NoTypeInformation
    
        if ((Get-Item $path).Length -gt 0) {
            Write-Host "Report finished and saved in $path" -ForegroundColor Green
        
            # Open the CSV file
            Invoke-Item $path
            }
            else {
            Write-Host "Failed to create report" -ForegroundColor Red
            }
        Set-Location C:\MHC
}

Function SecuirtyReport {
$s = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
Write-Host "------ Secuity Defaults ------"
$s | foreach { write-host ("Secuirty Defaults Enabled:", $_.IsEnabled, "`n") }
"`n`n"

$u = Get-MgIdentityConditionalAccessPolicy
Write-Host "------ Conditional Access ------"
$u | foreach { write-host ("Name:", $_.DisplayName, "`nState:", $_.State, "`n") }
"`n`n"

$x = Get-HostedContentFilterPolicy
Write-Host "------ Spam Policy ------"
$x | foreach { write-host ("Name:", $_.Name, "`nBackscatter:", $_.MarkAsSpamNdrBackscatter, "`nSPF Hard Fail:", $_.MarkAsSpamSpfRecordHardFail, "`nSender ID Hard Fail:", $_.MarkAsSpamFromAddressAuthFail, "`nSpam Quaratine Policy:", $_.SpamQuarantineTag, "`nHigh Confidence Spam Quarantine Tag:", $_.HighConfidenceSpamQuarantineTag, "`nPhish Quarantine Tag:", $_.PhishQuarantineTag, "`nHigh Confidence Phish Quarantine Tag:", $_.HighConfidencePhishQuarantineTag, "`nBulk Quarantine Tag", $_.BulkQuarantineTag, "`n") }
"`n`n"

$y = Get-MalwareFilterPolicy
Write-host "------ Malware Policy ------"
$y |  foreach { write-host ("Name:", $_.Name, "`nCommon Attachment Types Filter:", $_.EnableFileFilter, "`nFile Types:", $_.FileTypes, "`nPolicy Created:", $_.WhenCreated, "`nPolicy Last Changed:", $_.WhenChanged, "`nQuarantine Policy", $_.QuarantineTag, "`n" ) }
"`n`n"

$z = Get-QuarantinePolicy
Write-Host "------ Quaratine Policy ------"
$z | foreach { Write-host ("Name:", $_.Name, "`nQuaratine Permissions", $_.EndUserQuarantinePermissions, "`nNotifications:", $_.ESNEnabled, "`n") }
"`n`n"
}

Function DomainReport {
    $v = Get-AcceptedDomain
    Write-Host "------ Accepted Domains  ------"
    $v | foreach { write-host ("Name:", $_.Name, "`nValid:", $_.IsValid, "`n") }
    "`n`n"
    
    $w = get-dkimsigningconfig
    Write-Host "------ DKIM Config (Enabled  Domains Only) ------"
    $w | foreach { write-host ("Name:", $_.Name, "`nEnabled:", $_.Enabled, "`n") }
    "`n`n"
    
    $d = Get-AcceptedDomain
    Write-Host "------DMARC Config------"
    $d | foreach { get-DMARCRecord $_.name | FL}
        
}

Function AllTests {

#Connect Sessions 
ConnectSessions

#Start MFA Report 
MFAReport

#Start Security Report 
SecuirtyReport

#Start Domain Report
DomainReport

#Disconnect From Services
DisconnectSessions
}

Function MFATests {
   
ConnectSessions
#Start MFA Report 
MFAReport

#Disconnect From Services
DisconnectSessions
}

Function SecurityTests {
    ConnectSessions
#Start Security report
SecuirtyReport

#Disconnect From Services
DisconnectSessions
}

Function DomainTests {
    ConnectSessions
#Start Domain Report
DomainReport

#Disconnect from services
DisconnectSessions
}

# Used to decided with Tests to Run, All = AllTests, MFA = MFATests, Security = SecurityTests, Domain = DomainTests
Function StartTests {
DisconnectSessions
Write-Host "Which Test would you like to run `nFor All Tests: All `nFor MFA Only: MFA `nFor M365 Secuirty Checks only: Security `nFor Domain Checks only: Domain" -ForegroundColor Black -BackgroundColor Yellow
$answer = Read-Host "Selection:"
if ($answer -match "All") {
    AllTests
}

if ($answer -match "MFA") {
    MFATests
}



if ($answer -match "Security") {
    SecurityTests
}

if ($answer -match "Domain") {
    DomainTests
}
}

#Starts Script
StartTests

