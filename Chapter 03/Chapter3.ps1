##########                 CHAPTER 2                    #################
#########################################################################
#########################################################################
#Inside Cloud Shell or after installing AZ Module and Connecting to Azure
#########################################################################
#      If not in Cloud Shell, install and connect to Azure:
#########################################################################
#Install-Module -Name Az -Repository PSGallery -Force
#Import-module AZ
#Connect-AzAccount

#Verify the ip configurations
$a=(Get-AzVM -name DCAZROOT001)
(Get-AzNetworkInterface -Resourceid $a.NetworkProfile.Networkinterfaces.id).IpConfigurationsip 

#Modify the network ip configuration to staticaly assigned
$VM=(Get-AzVM -name DCAZROOT001)
$NIC=Get-AzNetworkInterface -Resourceid $VM.NetworkProfile.Networkinterfaces.id
$NIC.ipconfigurations[0].privateIPAllocationMethod = „Static”
Set-AzNetworkInterface -NetworkInterface $NIC

#########################################################################
#                             Inside Azure VM    #1                     #
#                     ROOT Domain Controller Promotion                  #
#########################################################################

#Prepare Windows features
Install-WindowsFeature RSAT-AD-TOOLS -IncludeAllSubFeature
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
#Capture DRSM Password
$Password = Read-Host -Prompt   'SafeModePassword' -AsSecureString
#Promote Domain Controller
$DomainName ="adpstest.net"
$DatabasePath = "C:\Windows\NTDS"
$SysVolPath = "C:\Windows\Sysvol"
$LogPath = "C:\Windows\NTDS"
$DomainNetbios = "ADPSTEST"
Install-ADDSForest -DomainName $DomainName -DatabasePath $DataBasePath `
-SysvolPath $SysVolPath -LogPath $LogPath -SafeModeAdministratorPassword $Password ` 
-DomainNetbiosName $DomainNetBios

#########################################################################
#                             Inside Azure VM  #2                       #
#                     CHILD Domain Controller Promotion  (EU Domain)    #
#########################################################################

#Prepare Windows features
Install-WindowsFeature RSAT-AD-TOOLS -IncludeAllSubFeature
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
#Capture DRSM Password
$Password = Read-Host -Prompt   'SafeModePassword' -AsSecureString
#Promote Child Domain Controller
$ParentDomainName ="adpstest.net"
$NewDomainName = "eu"
$NewDomainNetbiosName = "EU"
$DatabasePath = "C:\Windows\NTDS"
$SysVolPath = "C:\Windows\Sysvol"
$LogPath = "C:\Windows\NTDS"
$DomainNetbios = "ADPSTEST"
$Credential = Get-Credential -Message "Provide Root Domain Admin Credential" `
 -UserName "adpsadmin@adpstest.net"
Install-ADDSDomain -ParentDomainName $ParentDomainName  -DatabasePath $DataBasePath `
-SysvolPath $SysVolPath -LogPath $LogPath -SafeModeAdministratorPassword $Password `
-NewDomainName $NewDomainName -NewDomainNetbiosName $NewDomainNetbiosName -Credential $Credential

#########################################################################
#                             Inside Azure VM  #3                       #
#           CHILD Secondary Domain Controller Promotion  (EU Domain)    #
#########################################################################

#Prepare Windows features
Install-WindowsFeature RSAT-AD-TOOLS -IncludeAllSubFeature
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
#Capture DRSM Password
$Password = Read-Host -Prompt   'SafeModePassword' -AsSecureString
#Promote Child Domain Controller
$DatabasePath = "C:\Windows\NTDS"
$SysVolPath = "C:\Windows\Sysvol"
$LogPath = "C:\Windows\NTDS"
$DomainName = "eu.adpstest.net"
$Credential = Get-Credential -Message "Provide Child Domain Admin Credential" `
-UserName "adpsadmin@eu.adpstest.net"
Install-ADDSDomainController -DomainName $DomainNAme -LogPath $LogPath `
-SysVolPath $SysVolPath -DatabasePath $DatabasePath -SafeModeAdministratorPassword $Password `
-InstallDNS:$true -Credential $Credential

#########################################################################
#                             Inside Azure VM  #4                       #
#           CHILD Secondary Domain Controller Promotion  (EU Domain)    #
#########################################################################
#Prepare Windows features
Install-WindowsFeature RSAT-AD-TOOLS -IncludeAllSubFeature
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
#Capture DRSM Password
$Password = Read-Host -Prompt   'SafeModePassword' -AsSecureString
#Promote Child Domain Controller
$ParentDomainName ="adpstest.net"
$NewDomainName = "ap"
$NewDomainNetbiosName = "AP"
$DatabasePath = "C:\Windows\NTDS"
$SysVolPath = "C:\Windows\Sysvol"
$LogPath = "C:\Windows\NTDS"
$Credential = Get-Credential -Message "Provide Root Domain Admin Credential" `
 -UserName "adpsadmin@adpstest.net"
Install-ADDSDomain -ParentDomainName $ParentDomainName  -DatabasePath $DataBasePath `
-SysvolPath $SysVolPath -LogPath $LogPath -SafeModeAdministratorPassword $Password `
-NewDomainName $NewDomainName -NewDomainNetbiosName $NewDomainNetbiosName `
-Credential $Credential -CreateDNSDelegation
