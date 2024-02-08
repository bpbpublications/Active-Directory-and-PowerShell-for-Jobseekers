#############                 CHAPTER 7                    ##############
#########################################################################
#########################################################################
#                        Inside Azure VM    #1                          #
#                        ROOT DC - DCAZROOT001                          #
#########################################################################

#Verifying the permissions of OU in Active Directory
dsacls "OU=Workstations,OU=PL,OU=Office,DC=adpstest,DC=net"

#Verifying the permissions of OU in AD and saving it into the file
dsacls "OU=Workstations,OU=PL,OU=Office,DC=adpstest,DC=net" > c:\temp\permissionsReport.txt

#Verifying the permissions using the Get-ACL and AD PSProvider
Get-ACL "AD:OU=Workstations,OU=PL,OU=Office,DC=adpstest,DC=net" | fl

#Listing ACLs from the OU
(Get-ACL "AD:OU=Workstations,OU=PL,OU=Office,DC=adpstest,DC=net").access | fl

#Exporting the Permissions for specific AD Group 
(Get-ACL "AD:OU=Workstations,OU=PL,OU=Office,DC=adpstest,DC=net").access  | where {$_.IdentityReference -eq "ADPSTEST\PL_Workstations" } #Filtered

#Exporting list of Permissions for all objects 
(Get-ACL "AD:OU=Workstations,OU=PL,OU=Office,DC=adpstest,DC=net").access  | Export-CSV C:\temp\permissionsReport.csv  #All to CSV

###################################################################################################################################
#                                         Security Permissions Audit script for Active Directory 
###################################################################################################################################
#Initializing Variables
$ACLS=@();
$Objects = @();
$DomainDN = "DC=ADPSTEST,DC=NET"
$ReportPath = "c:\temp\permissionsReport.csv"

#Specifying the Search base for our search
$SearchBase = "OU=Office,$DomainDN"

#Getting Domain Object for listing permissions,
$Objects += get-adobject $DomainDN

#Getting AdminSDHolder object for listing permissions,
$objects += get-adobject "CN=AdminSDHolder,CN=System,$DomainDN"

#Getting all object from specific ad location
$Objects += get-adobject -filter * -SearchBase $SearchBase -SearchScope Subtree

foreach($object in $objects)
{
$DNName = $object.distinguishedName
$ACLS   += (Get-ACL "AD:$DNName").access | Add-Member -       NotePropertyName "ObjectDN" -NotePropertyValue $object.distinguishedName -PassThru |  Add-Member -NotePropertyName "ObjectClass" -NotePropertyValue $object.ObjectClass -PassThru
}

$ACLS  | export-csv c:\temp\permissions.csv
###################################################################################################################################
#                                                         Creating new blank GPO
###################################################################################################################################
New-GPO -Name DomainControllerHardeningGPO

#Import settings from Security Baseline GPO
Import-GPO -BackupGpoName "MSFT Windows Server 2022 - Domain Controller" -Path "C:\SecurityBaseline\W2k22\Windows Server-2022-Security-Baseline-FINAL\GPOs" -TargetName "DomainControllerHardeningGPO"

#Link GPO to the target OU
New-GPLink -Name "DomainControllerHardeningGPO" -Target "OU=Domain Controllers,DC=ADPSTEST,DC=NET"

#Set GPO order
Set-GPLink -Name "DomainControllerHardeningGPO"  -Target "OU=Domain Controllers,DC=ADPSTEST,DC=NET" -LinkEnabled Yes  -Order 1
##################################################################################################################################
#Getting list of AD privileged objects in AD
Import-Module ActiveDirectory
Get-ADObject -LDAPFilter "(admincount=1)"
##################################################################################################################################
#                                    Creation of MSA and gMSA account for testing purposes
##################################################################################################################################
#Create AD Key if not existing in the forest
$RootKey = $null
$RootKey = Get-KdsRootKey
if($RootKey -eq $null)
{
     Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
}
#Create AD Service Account
New-ADServiceAccount -Name MSA-AD-TEST -RestrictToSingleComputer
#Assign MSA to Server
Add-ADComputerServiceAccount -Identity DCAZROOT001 -ServiceAccount MSA-AD-TEST
#Create new gMSA account in domain
New-ADServiceAccount -name gMSA-AD-TEST -DNSHostName DCAZROOT001.adpstest.net
#Allow the server to use the gMSA account
Set-ADServiceAccount gMSA-AD-TEST -PrincipalsAllowedToRetrieveManagedPassword DCAZROOT001$

##################################################################################################################################
#                          Installing accounts and Scheduling the automation tasks on a server
##################################################################################################################################
#Install features if required – Not needed on already configured Domain Controller
#Add-WindowsFeature RSAT-AD-PowerShell

#Install MSA account
Install-ADServiceAccount -Identity MSA-AD-TEST

#Install gMSA account as well
Install-ADServiceAccount -Identity gMSA-AD-TEST

#Create directory if needed
New-Item -ItemType Directory -Path c:\temp
#CreateSchedule
$TimeTrigger = New-ScheduledTaskTrigger -At 12:00 -Weekly -DaysOfWeek Sunday
#Define the Action
$StartAction  = New-ScheduledTaskAction -Execute "hostname > c:\temp\hostname.txt"
#Specify the MSA or gMSA account to be used
$RunAsAccount = New-ScheduledTaskPrincipal -UserID adpstest\MSA-AD-TEST$ -LogonType Password
#Create ScheduledTask
Register-ScheduledTask -TaskName Test-MSA  -Principal $RunAsAccount -Trigger $TimeTrigger -Action $StartAction
#Specify the MSA or gMSA account to be used
$RunAsAccount = New-ScheduledTaskPrincipal -UserID adpstest\gMSA-AD-TEST$ -LogonType Password
#Create ScheduledTask
Register-ScheduledTask -TaskName Test-gMSA -Principal $RunAsAccount -Trigger $TimeTrigger -Action $StartAction

#################################################################################################################
#                                 Content of the scheduled task script
#################################################################################################################
try{
     Get-ADGroup "Delegation_Users"
}
catch{
    New-ADGroup -Name "Delegation_Users" -SamAccountName "Delegation_Users" -Path "OU=Delegation,OU=GlobalResources,DC=adpstest,DC=net" -GroupScope "Global" -GroupCategory Security
}
#OU name for users to be searched
$OUDN = "OU=Delegation,OU=GlobalResources,DC=adpstest,DC=net"

#Group name that will contain users as members
$ShadowGroup = "CN=Delegation_Users,OU=Delegation,OU=GlobalResources,DC=adpstest,DC=net"
#Cleanup of the membership that is no longer matching the OU
Get-ADGroupMember -Identity $ShadowGroup | Where{$_.distinguishedName -NotMatch $OUDN} | foreach-object {Remove-ADPrincipalGroupMembership -Identity $_ -MemberOf $ShadowGroup -Confirm:$False}

#Adding all users that are not yet member and form specific OU
Get-ADUser -LDAPFilter '(!memberOf=$OUDN)' -SearchBase $OUDN  | Foreach-Object {Add-ADGroupMember -Identity $ShadowGroup -Members $_}
##########################################################################################################################
#                                  Creation of Scheduled task for Dynamic Group test  
##########################################################################################################################
#Define the Trigger
$TimeTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 60)

#Define the Action
$StartAction  =  New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory "C:\Scripts\" -Argument '-NonInteractive -NoLogo -NoProfile -Command ".\DynamicGroup_Delegation_Users.ps1"'

#Specify gMSA account to be used
$RunAsAccount = New-ScheduledTaskPrincipal -UserID adpstest\gMSA-AD-TEST$ -LogonType Password

#Create ScheduledTask
Register-ScheduledTask DynamicGroup_Delegation_Users  -Principal $RunAsAccount -Trigger $TimeTrigger -Action $StartAction
##########################################################################################################################
#                               Creation and assigment of FGPP to Dynamic Group created
##########################################################################################################################
New-ADFineGrainedPasswordPolicy FGPP-DelegationUsers -ComplexityEnabled:$true -LockoutDuration:"00:30:00" `
-LockoutObservationWindow:"00:30:00" -LockoutThreshold:"5" -MaxPasswordAge:"30.00:00:00" `
-MinPasswordAge:"1.00:00:00" -MinPasswordLength:"15" -PasswordHistoryCount:"24" -Precedence:"1" `
-ReversibleEncryptionEnabled:$false -ProtectedFromAccidentalDeletion:$true
Add-ADFineGrainedPasswordPolicySubject FGPP-DelegationUsers -Subjects ‘Delegation_Users’
##########################################################################################################################
#                      Kerberos Delegation reporting and modification of unconstrained delegation settings
##########################################################################################################################
#Audit all Computer accounts with Unconstrained delegation, create test computer
Get-ADComputer -filter {TrustedForDelegation -eq $true}
New-ADComputer -Name TestComputer -SamAccountName TestComputer -Path "CN=Computers,DC=adpstest,DC=net"
#Audit all Users with Unconstrained delegation
Get-ADUser -filter {TrustedForDelegation -eq $true}

#Get the delegation settings for different computers
Get-ADComputer -Identity DCAZROOT001 -pr * | select name,TrustedForDelegation,TrustedToAuthForDelegation,PrincipalsAllowedToDelegateToAccount | fl

#Get the delegation settings for different computers
Get-ADComputer -Identity TestComputer -pr * | select name,TrustedForDelegation,TrustedToAuthForDelegation,PrincipalsAllowedToDelegateToAccount | fl

#Set unconstrained delegation for computer account or user account
Set-ADComputer -Identity TestComputer -TrustedForDelegation $True

##########################################################################################################################
#                     Kerberos Constrained delegation and modification of constrained delegation settings
##########################################################################################################################

#Audit all Computer accounts with Constrained delegation
Get-ADComputer -filter {msDS-AllowedToDelegateTo -like "*"}

#Audit all User accounts with Constrained delegation
Get-ADUser -filter {msDS-AllowedToDelegateTo -like "*"}

#Set contstrained delegation for computer account or user account - "Kerberos Only"
Set-ADComputer -Identity TestComputer -Add @{'msDS-AllowedToDelegateTo'=@('HOST/DCAZROOT001','WSMAN/DCAZROOT001.adpstest.net')}
Set-ADAccountControl -Identity TestComputer$ -TrustedToAuthForDelegation $False

#Set contstrained delegation for computer account or user account  -"Use any Authentication protocol"
Set-ADComputer -Identity TestComputer -Add @{'msDS-AllowedToDelegateTo'=@('HOST/DCAZROOT001','WSMAN/DCAZROOT001.adpstest.net')}
Set-ADAccountControl -Identity TestComputer$ -TrustedToAuthForDelegation $True

#Audit all Computer accounts with Constrained delegation
Get-ADComputer -filter {msDS-AllowedToDelegateTo -like "*"}


##########################################################################################################################
#               Kerberos resource based delegation reporting and modification of resource based delegation settings
##########################################################################################################################

#Audit all Computer accounts with Resource-Based Constrained Delegation
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'

#Audit all User accounts with  Resource-Based Constrained Delegation
Get-ADUser -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'

#Set Resource Based delegation for computer account
Set-ADComputer DCAZROOT001 -PrincipalsAllowedToDelegateToAccount TestComputer$

#Audit all Computer accounts with Resource-Based Constrained Delegation
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'

##########################################################################################################################
#                                          Microsoft Tiering model implementation 
##########################################################################################################################
#
#https://github.com/inntran/pawmedia.
#
#Create-PAWOUs.ps1 
#Create-PAWGroups.ps1

