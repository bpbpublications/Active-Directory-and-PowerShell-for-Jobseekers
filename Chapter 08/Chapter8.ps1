#############                 CHAPTER 8                    ##############
#########################################################################
#########################################################################
#                        Inside Azure VM    #1                          #
#                        ROOT DC - DCAZROOT001                          #
#########################################################################

#Getting details about NTDS Service
Get-Service NTDS

#Getting details about list of AD related services.
Get-Service NTDS,ADWS,DFS,DFSR,DNS,KDC,NETLOGON

#Getting the System log in PowerShell
Get-WinEvent -LogName System

#Getting System logs from specific provider
Get-WinEvent -FilterHashtable @{LogName='System’; ProviderName='Service Control Manager' }

#Getting System logs from specific provider and filtering based on specific message content
Get-WinEvent -FilterHashtable @{LogName='System';  ProviderName='Service Control Manager' } | where {$_.message -like "*NTDS*"}


#Executing DCDiag for specific domain controller

dcdiag /s:DCAZROOT001


#Executing DNS DCDiag test for specific domain controller

dcdiag /test:DNS /s:DCAZROOT001

###############################################################################################
#Automatizing DCDiag and parsing the output
###############################################################################################
$DCDiagResults = dcdiag 
Foreach($Line in $DCDiagResults) {
if($line -like "*failed test*" -or $line -like "*passed test*"){
write-host "$($line.split(' ')[10]) $($line.split(' ')[11]) $($line.split(' ')[12])"
}}
##############################################################################################
#Checking the replication for current DC
repadmin /showrepl

#Checking the replication summary for current DC
repadmin /replsummary

#Getting status of replication queue for current DC
repadmin /queue

#Checking status of DFSR replication

Install-WindowsFeature RSAT-DFS-Mgmt-Con
Get-DfsrState | select FileName,Inbound,UpdateState,SourceComputerName

###############################################################################################
#Automatizing listing of Logs related to Active Directory Service
###############################################################################################
Get-WinEvent -FilterHashTable @{LogName='Directory Service';Level=1,2,3;StartTime=((Get-Date).AddHours(-24));EndTime=(Get-Date)}
Get-WinEvent -FilterHashTable @{LogName='DFS Replication';Level=1,2,3;StartTime=((Get-Date).AddHours(-24));EndTime=(Get-Date)}
Get-WinEvent -FilterHashTable @{LogName='System';Level=1,2,3;StartTime=((Get-Date).AddHours(-24));EndTime=(Get-Date)}
Get-WinEvent -FilterHashTable @{LogName='Application';Level=1,2,3;StartTime=((Get-Date).AddHours(-24));EndTime=(Get-Date)}
Get-WinEvent -FilterHashTable @{LogName='DNS Server';Level=1,2,3;StartTime=((Get-Date).AddHours(-24));EndTime=(Get-Date)}
Get-WinEvent -FilterHashTable @{LogName='Active Directory Web Services';Level=1,2,3;StartTime=((Get-Date).AddHours(-24));EndTime=(Get-Date)}
Get-WinEvent -FilterHashTable @{LogName='Setup';Level=1,2,3;StartTime=((Get-Date).AddHours(-24));EndTime=(Get-Date)}
##############################################################################################

#Getting Performance Counter information
Get-Counter -Counter "\System\System Up Time"

#Getting information about processor utilization
Get-Counter -Counter "\Processor(*)\% Processor Time" -MaxSamples 2


##############################################################################################
#                             Scheduling the tasks for monitoring
##############################################################################################

#CreateTrigger every 5 minutes
$TimeTrigger = New-ScheduledTaskTrigger -At (Get-Date) -Once -RepetitionInterval (New-TimeSpan -Minutes 5)
#Specify SYSTEM account as principal
$Principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
#Define the Action
$StartAction = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy ByPass -NoProfile -File `"\\adpstest.net\SYSVOL\adpstest.net\scripts\DCDiag-Test.ps1`""
#Create ScheduledTask
Register-ScheduledTask DCDiag-Test  -Trigger $TimeTrigger -Action $StartAction -Principal $Principal

##############################################################################################
#                             New DCDiag Script test conntent 
##############################################################################################
New-EventLog -LogName “Application” -Source “DCDiag-Test” -ErrorAction SilentlyContinue
$DCDiagResults = dcdiag 
Foreach($Line in $DCDiagResults) { if($line -like “*failed test*” -or $line -like “*passed test*”) {Write-EventLog -LogName Application -Source “DCDiag-Test” -EventID 4001 -Message “$($line.split(‘ ‘)[10]) $($line.split(‘ ‘)[11]) $($line.split(‘ ‘)[12]) $($line.split(‘ ‘)[13])” } }

##############################################################################################
#                             KQL for getting information about services
##############################################################################################

ConfigurationData
| where SvcName in ("KdsSvc", "NTDS", "ADWS", "DFS", "DFSR", "DNS", "KDC", "NETLOGON")
| project SvcName, SvcDisplayName, SvcState

##############################################################################################
#Testing monitoring with disabling the service and stopping it
Set-Service -Name "kdssvc"  -StartupType Disabled

Stop-Service -Name "kdssvc" -Force