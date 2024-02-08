#############                 CHAPTER 10                  ###############
#########################################################################
#########################################################################
#                        Inside Azure VM -Core Server Deployed          #
#                        EU DC - DCAZEU003                              #
#########################################################################

#Installing AD roles
Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools

#Promoting Core server as AD Domain Controller
$creds=get-credential EU\adpstest
Install-ADDSDomainController -DomainName eu.adpstest.net -SysvolPath C:\Windows\SYSVOL -LogPath C:\Windows\NTDS -DatabasePath C:\Windows\NTDS -Credential $creds

#Enabling the Firewall Rules for WinRM

$Rules = @("Windows Remote Management","Windows Defender Firewall Remote Management", "Remote Event Log Management", "Remote Event Log Management", "Remote Volume Management", "Remote Scheduled Tasks Management")
$Rules | Enable-NetFirewallRule -DisplayGroup $_

#Enabling PS Remoting
Enable-PSRemoting -Force


#########################################################################
#                        Inside Azure VM                                #
#                        EU DC - DCAZEU001                              #
#########################################################################
#Remoting into server From different server

Enter-Pssession dcazeu003.eu.adpstest.net

#Calling WMIC procedure for creating new folder

WMIC /node:DCAZEU003 process call create '"cmd.exe /c mkdir c:\temp\test1"'

#Creating custom remote session and entering the session from remote server
New-PSSession -ComputerName DCAZEU003 -Name DC3Session
Enter-PSSession -Name DC3Session
#############################################
Hostname
$env:ComputerName
#############################################
Exit
Get-PSSession

#Getting powerShell commands that have session parameter implemented

Get-Command -ParameterName *session*
########################################################################
#Invoking simple ScriptBlock remotely 

$DCs= (Get-ADDomainController -filter * -server eu.adpstest.net).name
Invoke-Command -ScriptBlock { hostname } -ComputerName $DCs

########################################################################
#Invoking connectivity check remotely 
$ScriptBlock = {
       param
       (
              $DestHost = "DummyHost",
              $DestPort = 56789
       )
       $Test=Test-NetConnection -ComputerName $DestHost -Port $DestPort -InformationLevel Quiet
       return "$env:computername , $test"
}

$DCs=(Get-ADDomainController -Filter * -server eu.adpstest.net).name
Invoke-Command -ComputerName $DCs -ScriptBlock $ScriptBlock -ArgumentList "DCAZEU001","53"

########################################################################
# Running script block remotely with using the Job 
Invoke-Command -ComputerName $DCs -ScriptBlock $ScriptBlock -ArgumentList "DCAZEU001","53" -AsJob
Get-Job | Receive-Job -Wait
########################################################################
###########################Reporting Script #############################
########################################################################
# Preparing a script for reporting hotfixes on a server

$DCs=(Get-ADDomainController -Filter * -server eu.adpstest.net).name
$Hotfixes = Get-HotFix -ComputerName $DCs
$Hotfixes | Export-Csv C:\Reporting\ServersHotfixes.csv

Send-MailMessage -From 'reporting <reporting@adpstest.net>' -To 'adpsadmin <adpsadmin@adpstest.net' `
-Subject 'Hotfix Report' -Body "This is the Hotfix rerpot for EU domain " `
-Attachments C:\Reporting\ServerHotfixes.csv -Priority High -SmtpServer 'smtp.adpstest.net'

########################################################################
#Creating Service Account for a script
New-ADServiceAccount adpatchrep -PrincipalsAllowedToRetrieveManagedPassword (get-adgroup "Domain Controllers" -server eu.adpstest.net ).distinguishedname -DNSHostName eu.adpstest.net
Add-ADGroupMember "Domain Admins" -Members adpatchrep$ -server eu.adpstest.net
Install-ADServiceAccount adpatchrep
########################################################################
#Scheduling a script inside as a scheduled task

#CreateTrigger every Day
$TimeTrigger = New-ScheduledTaskTrigger -Daily -At '00:00'
#User adserviceaccount
$Principal = New-ScheduledTaskPrincipal -UserID "EU\adpatchrep$" -LogonType Password -RunLevel Highest
#Define the Action
$StartAction = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '-ExecutionPolicy Unrestricted -NoProfile -File "C:\Reporting\HotfixReporting.ps1"'
#Create ScheduledTask
Register-ScheduledTask HotfixReporting  -Trigger $TimeTrigger -Action $StartAction -Principal $Principal

########################################################################
###########################Reporting Hybrid worker######################
########################################################################
#Preparing script for hybrid worker

#Make sure server that is running hybrid worker is having RSAT AD Powershell tools installed
Import-Module ActiveDirectory
$DCs=(Get-ADDomainController -Filter * -server eu.adpstest.net).name
$Hotfixes = Get-HotFix -ComputerName $DCs
$Hotfixes | Export-Csv C:\Reporting\ServersHotfixes.csv
return $Hotfixes

#Hybrid worker Template file content (commented)


#    "inputs": {
#        "parameters": {
#            "subscriptionId": "8c1c22ae-21d8-4a8c-a4dc-43aae2c76a90",
#            "resourceGroup": "Res-Group-Dev-ADTest",
#            "automationAccount": "AA-ActiveDirectory2",
#            "runbookName": "ReportingHotfixes",
#            "hybridAutomationWorkerGroup": "Hotfix"
#        },
#        "serviceProviderConfiguration": {
#            "connectionName": "azureAutomation",
#            "operationId": "createJob",
#            "serviceProviderId": "/serviceProviders/azureAutomation"
#        }
#    }
#}

#Steps imputs definition  

#"inputs": {
#                    "variables": [
#                        {
#                            "name": "Hotfixes",
#                            "type": "string",
#                            "value": "@body('Get_Job_Output')"
#                        }
#                    ]
#                },
