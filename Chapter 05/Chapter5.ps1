#############                 CHAPTER 5                    ##############
#########################################################################
#########################################################################
#                        Inside Azure VM    #1                          #
#                        ROOT DC - DCAZROOT001                          #
#########################################################################

#Registration of AD Schema admin console
regsvr32 schmmgmt.dll

#Simple creation of User Account
Import-Module ActiveDirectory
New-ADUser -Name John.Nowak -SamAccountName john.nowak -userprincipalname john.nowak@adpstest.net
#Simple creation of User Account #2
Import-Module ActiveDirectory
New-ADUser -Name John.Nowak2 -SamAccountName john.nowak2 -userprincipalname john.nowak2@adpstest.net

#Resetting user password and enable user account
Set-ADAccountPassword -Identity john.nowak2 -Reset #You will be prompted for password if no newpassword parameter is specified as secure string
Set-ADUser -Identity john.nowak2 -Enabled $true

#Moving User account to different OU from standard container

##TargetPath need to be in same domain source location and the same as domain controller we execute commands
##We could specify server parameters in all functions if we perform operations from endpoint in different domain “-server”. Sometimes it is domain parameter for specific operations.
$User = Get-ADUser john.nowak2
Move-ADObject -Identity $User.DistinguishedName -TargetPath "OU=StandardUsers,OU=PL,OU=Office,DC=adpstest,DC=net"
Set-ADUser -Identity john.nowak2 -DisplayName John.Nowak2 -GivenName John -Surname Nowak
Get-ADUser -Identity john.nowak2

#Getting detailed report about user objects with information about the creation, logon and password change timings.
get-aduser john.nowak2 -pr whenCreated,pwdLastSet,LastLogonDate,LastLogonTimeStamp,lastLogon,PasswordLastSet

#Disabling user account
Get-ADUser John.Nowak2 | Set-ADUser -Enabled $false

#Renaming user account in PowerShell
Get-ADUser John.Nowak
Get-ADUser John.Nowak | Set-ADUser -DisplayName John.Nowak3 -SamAccountName john.nowak3 -UserPrincipalName john.nowak3@adpstest.net
Get-ADUser John.Nowak3 | Rename-ADObject -NewName John.Nowak3
Get-ADUser John.Nowak3

#Changing the aditional attributes values for user accounts (employeeType)
Get-ADUser John.Nowak3 -pr employeeType
Get-ADUser John.Nowak3 | Set-ADUser -Replace @{employeeType="internal"}
Get-ADUser John.Nowak3 -pr employeeType

#Modification of user expiration date in AD

Get-ADUser John.Nowak3 -pr AccountExpirationDate
Get-ADUser John.Nowak3 | Set-ADAccountExpiration -DateTime "06/14/2023"
Get-ADUser John.Nowak3 -pr AccountExpirationDate


#Getting the list of all users in AD(current domain)
Get-ADUser -filter *

#Getting the list of only enabled users
Get-ADUser -filter {Enabled -eq $True}

#Changing the output formatting to table 
Get-ADUser -filter {Enabled -eq $True} | FT

#Quering for specific parameters and selecting the specific columns 
Get-ADUser -filter * -properties Enabled,whenCreated | Select Name, SamAccountName, DistinGuishedName,Enabled
Get-ADUser -filter {Enabled -eq $True} -properties Enabled,whenCreated | Select Name, SamAccountName, DistinguishedName, Enabled

#Quering users from specific OU 
Get-ADUser -SearchBase "OU=PL,OU=Office,DC=adpstest,DC=net" -SearchScope Subtree -filter {Enabled -eq $True} `
-properties Enabled,whenCreated | Select Name, SamAccountName, DistinGuishedName,Enabled

#Reporting users from global catalog to the txt file
Get-ADUser -Server adpstest.net:3268 -filter {Enabled -eq $True} `
-properties Enabled,whenCreated | Select Name, SamAccountName, DistinGuishedName,Enabled  | out-file c:\temp\report.txt

#Reporting users from global catalog to CSV file
Get-ADUser -Server adpstest.net:3268 -filter {Enabled -eq $True} `
-properties Enabled,whenCreated | Select Name, SamAccountName, DistinGuishedName,Enabled  | export-csv c:\temp\report.csv

#Importing users from CSV file and creating them in Active Driectory 
$Users = import-csv c:\temp\import.csv
Foreach ($User in $Users)
{
    Write-Host "Creating User: $($User.Name)"
    New-ADUser -Name $User.Name -SamAccountName $User.SamAccountName -UserPrincipalName $USer.UserPrincipalName -DisplayName $User.Name -Path $User.Path
}

#Setting description of the users imported from CSV
$Users = import-csv c:\temp\import.csv
Foreach ($User in $Users)
{
    Write-Host "Modifying User: $($User.Name)"
    Get-ADUser -Identity $User.Name | Set-ADUser -Description $User.Description
}

#Setting up specific logon hours using powershell
[byte[]]  $logonhours = @(0,0,0,0,255,3,0,255,3,0,255,3,0,255,3,0,255,3,0,0,0)
Get-ADUser -Identity adpsadmin | Set-ADUser -Replace @{logonhours = $logonhours }

#Reseting user password using Powershell
Get-ADUser -Identity adpsadmin | Set-ADAccountPassword -Reset