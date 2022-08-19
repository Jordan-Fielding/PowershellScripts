<# Required Module for PowerShell 
Install-Module SharePointPnPPowerShellOnline #>


<# Once this is installed you can nun the following which will connect you to the SharePoint online file Server (NOT TO BE CONFUSED WITH SPO AS IT IS DIFFERNET)
Change the following details to suit your client #>
$Domain = 'domain'
$Username = 'username' 
$SharepointSite = 'General'
 
#Sets date range one, make this the earliest date the data could be missing. If the data doesn't show up try expanding your search by 1 day if you are searching for a specific day
$date1 = get-date('02/08/2022')
#Sets date range two, make this the latest date the data could be missing.
$date2 = get-date('31/07/2022')


#Do not alter the following details
$siteurl = 'https://' + $Domain + '.sharepoint.com/Sites/' + $SharepointSite
$Emailaddress = $Username + "@" + $Domain + '.com'




#Connects you to SharepointPnPPowerShell, If you are running this manually then comments out the below once you have connected
Connect-PnPOnline -url $siteurl -UseWebLogin
 
#The below will list out all the items in the PowerShell window 
Get-PnPRecycleBinItem  -FirstStage | ? {($_.DeletedByEmail -eq $Emailaddress) -and ($_.DeletedDate -gt $date2 -and $_.DeletedDate -lt $date1)}


#Uncomment the below command when you have found your date range, the below command will restore all items in the filters
#Get-PnPRecycleBinItem -FirstStage | ? {($_.DeletedByEmail -eq $Username) -and ($_.DeletedDate -gt $date2 -and $_.DeletedDate -lt $date1)} | Restore-PnpRecycleBinItem -Force








<# Below are the extra options that can be use with the filters 
DeletedByEmail - Specifiecs the email 
Used in the following way 
DeletedByEmail -eq email@domain.com 
DeletedDate - Specifies the deletes date
Used in the following way
DeletedDate -gt '01/01/1900'
Extra items are listed here 
https://pnp.github.io/powershell/cmdlets/Get-PnPRecycleBinItem.html#>