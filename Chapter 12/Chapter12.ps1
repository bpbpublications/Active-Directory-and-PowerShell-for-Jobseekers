#############                 CHAPTER 12                   ##############
#########################################################################
#########################################################################
#                                                                       #
#                   Inside Azure VM -Core Server Deployed               #
#                        EU DC - DCAZEU003                              #
#                                                                       #
#########################################################################


#Create Temp Folder Configuration
#Preparing Configuration Directory
if(!(test-path C:\Dsc))
{
    new-item C:\Dsc -ItemType Directory
}
Set-Location C:\Dsc

#Defining Configuration
Configuration CreateTempFolder {

#Importing Basic DSC Module
Import-DscResource -ModuleName PsDesiredStateConfiguration

#Defining Node Configuration
Node ‘DCAZEU003’ {
            #Calling File Resouce with specifying the folder creation
    		File CreateTemp {
      			Ensure = “Present”
      			DestinationPath = “C:\Temp”
			Type = ”Directory”
    		}
  	}
}

#Compiling DSC Configuration
CreateTempFolder
##################################################################################

#Compiling config
Start-DscConfiguration -Path C:\Dsc\CreateTempFolder -Wait -Verbose

#Re applying config on remote server 

Remove-Item \\DCAZEU003\c$\temp
Start-DscConfiguration -Path C:\Dsc\CreateTempFolder -Wait -Verbose
###################################################################################
###################################################################################
#                               Azure Automation DSC                              #

Mkdir DSCConfigs
Cd DSCConfigs
# Define the parameters for Get-AzAutomationDscOnboardingMetaconfig using PowerShell Splatting
$Params = @{
    ResourceGroupName = 'Res-Group-Dev-ADTest'; # The name of the Resource Group that contains your Azure Automation account
    AutomationAccountName = 'AA-ConfigurationManagement'; # The name of the Azure Automation account where you want a node on-boarded to
    ComputerName = @('DCOPEU005', 'DCOPEU006'); # The names of the computers that the metaconfiguration will be generated for
    OutputFolder = ".\”
}
# Use PowerShell splatting to pass parameters to the Azure Automation cmdlet being invoked
# For more info about splatting, run: Get-Help -Name about_Splatting
Get-AzAutomationDscOnboardingMetaconfig @Params

###################################################################################
###################################################################################

#Aplying LCM Config on Server

#Helper commands to verify the server we execute the command locally or remotely
$env:computername
#Checking name of the downloaded file as it is taken from Azure Cloud Shell
dir
#Trying to configure the LCM
Set-DscLocalConfigurationManager -Path ".\" -ComputerName "DCOPEU005"
#Fixing the naming convention issues for the DSCMetaConfig file
Rename-Item .\DscMetaConfigsDCOPEU005.meta.mof .\DCOPEU005.meta.mof
#Retrying the LCM Configuration
Set-DscLocalConfigurationManager -Path ".\" -ComputerName "DCOPEU005"

###################################################################################
###################################################################################
#                               Server without Internet module import

#Run on client with internet
Install-Module ActiveDirectoryDSC

#If we do not have access to internet or the PowerShell Gallery, we need to save module on the client that has this access and then copy it into the destination server modules folder:

Save-Module ActiveDirectoryDSC -Path C:\temp
Copy-Item C:\temp\ActiveDirectoryDsc -Destination “\\$DestinationServer\C$\Program Files\WindowsPowerShell\Modules\”



###################################################################################
###################################################################################
#                               DSC Configuration of Domain Controller


Configuration PromoteEUDomainController
{

    $ADDomainName = "eu.adpstest.net"
    $DomainNetBios = "EU"
    $KeyVaultName = "KeyVault-DSC-AD"
    $SecretUserName = "DomainAdminName"
    $SecretUserPassword = "DomainAdminPassword"
    $SafeModeSecretName = "SafeModePassword"

    #Connect to Automation Account
    Connect-AzAccount -Identity
    #Get Domain Admin Username
    $UserName = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -AsPlainText
    #Get Domain Admin Password
    $Password = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserPassword -AsPlainText
    #Convert to Secure String
    $PasswordString = ConvertTo-SecureString -String $Password -AsPlainText -Force
    #Build the Credential Object
    $DACredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList "${DomainNetBios}\${UserName}", $PasswordString

    #Get SafeMode Password
    $SafeModePassword = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SafeModeSecretName -AsPlainText
    #Convert to Secure String
    $SafeModePasswordString = ConvertTo-SecureString -String $SafeModePassword -AsPlainText -Force
    #Build the Safe Mode Credential Object
    $SafeModeCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList "SafeMode", $SafeModePasswordString


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node localhost
    {
     
        WindowsFeature 'ADDSFeature'
        {
            Ensure = 'Present'
            Name   = 'AD-Domain-Services'
        }

        WindowsFeature 'ADTools'
        {
            Ensure    = 'Present'
            Name      = 'RSAT-AD-TOOLS'
            IncludeAllSubFeature = $True
            DependsOn = '[WindowsFeature]ADDSFeature'
        }
       
        WaitForADDomain 'WaitForestAvailability'
        {
            DomainName = $ADDomainName
            Credential = $DACredential
            DependsOn  = '[WindowsFeature]ADTools'
        }
       
        ADDomainController 'DomainControllerMinimal'
        {
            DomainName                     = $ADDomainName
            Credential                     = $DACredential
            SafeModeAdministratorPassword  = $SafeModeCredential
            SysVolPath             = "C:\Windows\Sysvol"
            DatabasePath          = "C:\Windows\NTDS"
            LogPath             = "C:\Windows\NTDS"
            InstallDNS             = $True
            DependsOn                       = '[WaitForADDomain]WaitForestAvailability'
        }
    }
}

###################################################################################
###################################################################################

#Updating Configuration on the Server

#Update config
Update-DSCConfiguration -Wait -Verbose

#Just to Retry existing config:
Start-DSCConfiguration -UseExisting
