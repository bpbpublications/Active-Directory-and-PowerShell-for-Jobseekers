#############                 CHAPTER 9                    ##############
#########################################################################
#########################################################################
#                        Inside Azure VM    #1                          #
#                        ROOT DC - DCAZROOT001                          #
#########################################################################

#Listing test user deleted in AD
Get-adobject -IncludeDeletedObjects -filter 'Deleted -eq $true -and CN -like "TEST*"'

#Restoring user object from recycle bin
get-adobject -IncludeDeletedObjects -filter 'Deleted -eq $true -and CN -like "TEST*"'  `
| Restore-ADObject -NewName "Test"

#Restinging user object to different path  and with new name
get-adobject -IncludeDeletedObjects -filter 'Deleted -eq $true -and CN -like "adpsadmin10*"'  `
| Restore-ADObject -NewName "adpsadmin10" -TargetPath "OU=Delegation,OU=GlobalResource,DC=adpstest,DC=net"


#########################################################################
#                   Configure Local Backup for Domain Controller

#Specify Disk number before proceeding
$DiskNumber  = 2
$Policy      = New-WBPolicy
#Add Backup Items
$Volumes     = Get-WBVolume -AllVolumes
Add-WBBareMetalRecovery  -Policy $Policy
Add-WBVolume             -Volume $Volumes -Policy $Policy
#Add Backup Target
$Disk             = Get-WBDisk | Where {$_.DiskNumber -eq $DiskNumber}
$BackupLocation   = New-WBBackupTarget -Disk $Disk -Label “Backup Disk”
Add-WBBackupTarget -Target $BackupLocation -Policy $Policy
#Remove Backup Disk from Backups
$BackupVolume     = Get-WBVolume -Disk $Disk
$TempStorage      = Get-WBVolume -VolumePath D:
Remove-WBVolume -Volume $BackupVolume -Policy $Policy
Remove-WBVolume -Volume $TempStorage -Policy $Policy
#Create Schedule
Set-WBSchedule     -Policy $Policy -Schedule 23:30
Set-WBPolicy       -Policy $Policy -Force

#########################################################################

#Setting the next boot into DSRM mode

Bcdedit /set safeboot dsrepair

#########################################################################
#                        Inside Azure VM #1     SAFE MODE               #
#                        ROOT DC - DCAZROOT001  SAFE MODE               #
#########################################################################
#######################  Authoritative AD Restore  ######################
#Checking local backup versions
wbadmin get versions

#Checking the backup drives
wbadmin get disks

#Checing local backup from specific target volume
wbadmin get versions -backuptarget:"\\?\Volume{6e8a86af-fd35-4dae-b5ed-3b065e15c1ac}"

#Starting system state recovery
wbadmin start systemstaterecovery -version:"01/15/2023-17:10"

#Starting authoritative restore
ntdsutil
activate instance ntds
authoritative restore

#Restoring entire AD partition authoritative
Restore subtree DC=adpstest,DC=net

#Removing safe mode flag for normal boot
bcdedit /deletevalue safeboot

#########################################################################
####                        OU Restore                                ###

#Setting the next boot into DSRM mode

#Bcdedit /set safeboot dsrepair

#Starting the restore
ntdsutil
activate instance ntds
authoritative restore

#Restoring only specific OU
restore subtree CN=Users,DC=adpstest,DC=net

#Removing safe mode flag for normal boot
#bcdedit /deletevalue safeboot


#########################################################################
####                        Object Restore                            ###

#Setting the next boot into DSRM mode

#Bcdedit /set safeboot dsrepair

#Starting the restore
ntdsutil
activate instance ntds
authoritative restore

#Restoring specific object
restore object “CN=domain admins,CN=Users,DC=adpstest,DC=net”

#Removing safe mode flag for normal boot
#bcdedit /deletevalue safeboot

#########################################################################
####                   Sysvol recovery                                ###

#Setting the next boot into DSRM mode
Bcdedit /set safeboot dsrepair

#Starting the system state recovery 
wbadmin start systemstaterecovery -version:"01/18/2023-00:28" -authsysvol


##Folow up with Authoritative or Non Authoritative restore after reboot##

Removing safe mode flag for normal boot
#bcdedit /deletevalue safeboot


#########################################################################
####                Non-Authoritative Sysvol synchronization          ###


#Disable DFSR replication 
Set-ADObject "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DCAZEU001,OU=Domain Controllers,DC=eu,DC=adpstest,DC=net" -Replace @{"msDFSR-Enabled"="FALSE"}

#Push replication of config
repadmin /syncall

#Force restore
DFSRDIAG POLLAD

#Restore replication

Set-ADObject "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DCAZEU001,OU=Domain Controllers,DC=eu,DC=adpstest,DC=net" -Replace @{"msDFSR-Enabled"="TRUE"}
repadmin /syncall
DFSRDIAG POLLAD


#########################################################################
####                Authoritative Sysvol synchronization              ###

#Stop DFSR Service on ALL servers - need to be executed on every server inside domain
Set-Service DFSR -StartupType Manual -PassThru | Stop-Service
Get-Service DFSR

#Disable Replication on authoritative server
Set-ADObject "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DCAZEU001,OU=Domain Controllers,DC=eu,DC=adpstest,DC=net" -Replace @{"msDFSR-Enabled"="FALSE"}
#Set server as authoritative
Set-ADObject "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DCAZEU001,OU=Domain Controllers,DC=eu,DC=adpstest,DC=net" -Replace @{"msDFSR-options"="1"}

#Set ALL!!! other servers to replicatie changes from Authoritative server
Set-ADObject "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=HOSTNAME,OU=Domain Controllers,DC=eu,DC=adpstest,DC=net" -Replace @{"msDFSR-options"="1"}

#Sync Config
repadmin /syncall

#Start DFSR on authoritative server
Set-Service dfsr -StartupType Automatic -PassThru | Start-Service

#Set authoriative server to normal operation
Set-ADObject "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DCAZEU001,OU=Domain Controllers,DC=eu,DC=adpstest,DC=net" -Replace @{"msDFSR-Enabled"="TRUE"}

#Sync Config
repadmin /syncall
DFSRDIAG POLLAD

#Start DFSR service on ALL other DC's

Set-Service dfsr -StartupType Automatic -PassThru | Start-Service

#Enable replication on ALL other DC's
Set-ADObject "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=HOSTNAME,OU=Domain Controllers,DC=eu,DC=adpstest,DC=net" -Replace @{"msDFSR-Enabled"="TRUE"}
DFSRDIAG POLLAD



