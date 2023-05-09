
Function ConnectMsolService {
    if (-not(Get-InstalledModule MSOnline )) {
        Write-Host "Would you like to install Msol Service?" -ForegroundColor Black -BackgroundColor Yellow
        $installmsol = Read-Host "Y/N"

        if ($installmsol -match "[Yy]") {
            Install-Module MSOnline
        }
        else {
            Write-Host "MS Online module is required." -ForegroundColor Black -BackgroundColor Red
            exit
        } 
    }
    Write-Host "Connecting to MS Online" -ForegroundColor Cyan
    Connect-MsolService
}

Function ConnectTo-EXO {
   
    if (-not(Get-InstalledModule ExchangeOnlineManagement)) { 
        Write-Host "Microsoft EXO module not found" -ForegroundColor Black -BackgroundColor Yellow
        $install = Read-Host "Do you want to install the Microsoft EXO Module?"

        if ($install -match "[Yy]") {
            Install-Module ExchangeOnlineManagement 
        }
        else {
            Write-Host "Microsoft EXO module is required." -ForegroundColor Black -BackgroundColor Yellow
            exit
        } 
    }

    
    Write-Host "Connecting to Microsoft EXO" -ForegroundColor Cyan
    Connect-exchangeonline
}

Function MailboxSharing {
Write-Host "What is the email you are sharing?"
$CurrentUser = Read-Host "Name?"

Get-MsolUser -All | Where-Object { $_.isLicensed -eq "TRUE" -and $_.licenses.AccountSkuId -like "*O365_BUSINESS_PREMIUM*" } | ForEach-Object {
    $UserPrincipalName = $_.UserPrincipalName
    if($CurrentUser -ne $UserPrincipalName) {
    Add-MailboxPermission -Identity $CurrentUser -User $UserPrincipalName -AccessRights ReadPermission, FullAccess
    }
}
Get-MailboxPermission -Identity $CurrentUser | Where-Object { $_.AccessRights -ne "None" } | Select-Object User, AccessRights
}
Function DisconnectSessions {
    Write-host "DISCONNECTING PERVIOUS SESSIONS" -ForegroundColor Black -BackgroundColor Red
    #Disconnect From Services
    Disconnect-ExchangeOnline
    }
Function ScriptMenu {
    Write-Host "This script is used to programticlly assign all users with a Valid M365 Business Standard License Read and Manage Permissions to your mailbox, `n Starting Script....."-ForegroundColor Black -BackgroundColor Yellow
    DisconnectSessions
    ConnectMsolService
    ConnectTo-EXO
    MailboxSharing
    DisconnectSessions

    Write-Host "Would you like to assign read / manage access to another mailbox?" -ForegroundColor Black -BackgroundColor Yellow
    $Answer = Read-Host "Y/N?"

    if ($Answer -match "[Yy]") {
        MailboxSharing
    }
    if ($Answer -match "[Nn]") {
        Exit 0
    }
    else {
        Write-Host "Invalid Answer, Please loas script again"
        Exit 0
    }
}
ScriptMenu