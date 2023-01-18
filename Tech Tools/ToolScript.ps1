Function TestConnection {
    Write-Host "Specifiy HostName or IP" -ForegroundColor Black -BackgroundColor Yellow
    $computername = Read-Host "Host"
    "`n`n"
    Write-Host "Specifiy Port #" -ForegroundColor Black -BackgroundColor Yellow
    $portnumber = Read-Host "Port"
    "`n`n"

    test-netconnection -computername $computername -port $portnumber
    "`n`n"
}
Function AddUser {
    Write-Host "What is the name of the new user?" -ForegroundColor Black -BackgroundColor Yellow
    $newusername = Read-Host "Username"
    "`n`n"
    Write-Host "What Password would you like?" -ForegroundColor Black -BackgroundColor Yellow
    $newuserpassword = Read-Host "Password"
    "`n`n"

    net user $newusername $newuserpassword /add
    "`n`n"

    Write-Host "Would you like to make this user a local admin as well?" -ForegroundColor Black -BackgroundColor Yellow
    $RequestAdmin = Read-Host "Y/N"
    "`n`n"
    if ($RequestAdmin -match "[y/Y]"){
        net localgroup administrators $newusername /add
        "`n`n"
    }
}
Function DelUser {
    
    Write-host "Below are the currnet users on the PC" -ForegroundColor Black -BackgroundColor Yellow
    "`n`n"
    net user
    "`n`n"
    Write-Host "What User would you like to remove?" -ForegroundColor Black -BackgroundColor Yellow
    $selecteduser = Read-Host "Selection"
    "`n`n"
    Write-Host "You have Selected $selecteduser`nIs this correct?"
    $confirmation = Read-Host "Y/N"
    "`n`n"
    if($confirmation -match "[yY]"){
        net user $selecteduser /delete
        "`n`n"
    }
    if($confirmation -match "[nN]"){
        Write-Host "Would you like to select again or go back to the menu?`n1: To Try again`n2: to go back to Menu `n3: To Quit"
        $confirmationchoice = Read-Host "Selection"
        "`n`n"
        if($confirmationchoice -match "1"){
            Write-Host "Starting Again...."-ForegroundColor Black -BackgroundColor Green
            "`n`n"
            Start-Sleep -Seconds 2
            DelUser
        }
        if($confirmationchoice -match "2"){
            Write-Host "Going back to Menu......"-ForegroundColor Black -BackgroundColor Green
        "`n`n"
        Start-Sleep -Seconds 2
        ToolScript
        }
        if($confirmationchoice -match "3"){
            Write-Host "ToolScript is now ending...." -ForegroundColor Black -BackgroundColor Green
            "`n`n"
            Start-Sleep -Seconds 2
            exit
        }
        else{
            Write-Host "Starting Again...."-ForegroundColor Black -BackgroundColor Green
            "`n`n"
            Start-Sleep -Seconds 2
            DelUser
        }
    }
}





Function MenuOptions {
    Write-Host "Which Tool would you like to use? `n1: For TCP Connection Test `n2: For New User Creation `n3: For User Deletion" -ForegroundColor Black -BackgroundColor Green
    $menuselection = Read-Host "Selection"
    "`n`n"
    if($menuselection -match "1") {
        TestConnection
    }
    if($menuselection -match "2") {
        AddUser
    }
    if($menuselection -match "3"){
        DelUser
    }
}

Function MenuLoopBack {
    Write-Host "Would you like to go back to the Menu?" -ForegroundColor Black -BackgroundColor Yellow
    $menuselection1 = Read-Host "Y/N"
    "`n`n"
    if ($menuselection1 -match "[yY]") {
        Write-Host "Going back to Menu......"-ForegroundColor Black -BackgroundColor Green
        "`n`n"
        Start-Sleep -Seconds 2
        ToolScript
    }
    else {
        Write-Host "ToolScript is now ending...." -ForegroundColor Black -BackgroundColor Green
        "`n`n"
        Start-Sleep -Seconds 2
        exit
    }
}
Function ToolScript {
    MenuOptions
    MenuLoopBack
}


ToolScript

