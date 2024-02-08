#############                 CHAPTER 11                   ##############
#########################################################################
#########################################################################
#                        Inside Azure VM -Core Server Deployed          #
#                        EU DC - DCAZEU003                              #
#########################################################################

#Checking the WINRM Settings
Get-PSSessionConfiguration
winrm get winrm/config

#Disabling the PSRemoting functions
Disable-PSRemoting -Force


#Configuration of HTTPS listener for WINRM

#Create Cert
$WinRMCert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName "dcazeu003.eu.adpstest.net"
#List Listeners
Get-ChildItem -Path WSMan:\Localhost\listener\listener*
#Create Listener
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $WinRMCert.Thumbprint
#List Listeners
Get-ChildItem -Path WSMan:\Localhost\listener\listener*

#Verification of WINRM Configuration
Enter-PSSession -ComputerName LocalHost -UseSSL

#Importing cert to trusted store  and testingt the secure connection

Export-Certificate -Cert $WinRMCert -FilePath C:\temp\WinRMCert
Import-Certificate -FilePath C:\temp\WinRMCert -CertStoreLocation Cert:\LocalMachine\Root
Enter-PSSession -ComputerName localhost -UseSSL

#Optional removal of HTTP Listener
Get-ChildItem -Path WSMan:\Localhost\listener\listener* | Where {$_.Keys -contains "Transport=HTTP"}  | Remove-Item

#Modification of the port to different one
Get-ChildItem -Path WSMan:\Localhost\listener\listener* | Where {$_.Keys -contains "Transport=HTTPS"} | Get-ChildItem | Where {$_.Name -eq "Port"} | Set-Item -Value 8888


#Checking the Authentication settings for WINRM

#Check WINRM server component authentication settings:
Get-ChildItem -Path WSMan:\localhost\Service\Auth\

#Check WINRM client component authentication settings:
Get-ChildItem -Path WSMan:\localhost\Client\Auth\

#Check settings
Get-ChildItem -Path WSMan:\localhost\Service\Auth\

#Check Basic Authentication 
Enter-PSSession -ComputerName DCAZEU003.eu.adpstest.net -UseSSL -Port 8888 -Authentication Basic

#Check Negotiate Authentication 
Enter-PSSession -ComputerName DCAZEU003.eu.adpstest.net -UseSSL -Port 8888 -Authentication Negotiate
Exit

#Check Kerberos Authentication
Enter-PSSession -ComputerName DCAZEU003.eu.adpstest.net -UseSSL -Port 8888 -Authentication Kerberos
Exit


#Configuration of Certificate for WINRM authentication

#Create Certificate
$ClientCert = New-SelfSignedCertificate -KeyUsage DigitalSignature,KeyEncipherment -CertStoreLocation Cert:\CurrentUser\My\ -Type Custom -Subject adpsadmin@adpstest.com -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=adpsadmin@adpstest.com")

#Check Certificate
$ClientCert

#Export Certificate
$ClientCert | Export-Certificate -FilePath c:\temp\ClientCert.crt

#Import Cert to Trusted People Store
Import-Certificate -FilePath C:\temp\ClientCert.crt -CertStoreLocation Cert:\LocalMachine\TrustedPeople

#Import Cert to Trusted Root Store
Import-Certificate -FilePath C:\temp\ClientCert.crt -CertStoreLocation Cert:\LocalMachine\Root

#Enable Cert Auth
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

#Map cert to local account
New-Item -Path WSMan:\localhost\ClientCertificate -Subject 'adpsadmin@adpstest.com' -Issuer 278445759CAADC9BB57CF2836AD7E25DC722893C -Credential (Get-Credential EU\adpsadmin)



#Test Certificate Authentication
Enter-PSSession -ComputerName DCAZEU003.eu.adpstest.net -UseSSL -Port 8888 -CertificateThumbprint 278445759CAADC9BB57CF2836AD7E25DC722893C
Exit


#Enabling firewall for WINRM custom port



#Get IPfilter values for WINRM service
Get-ChildItem -Path WSMan:\localhost\Service\IP*Filter

#Get WINRM listeners details
Get-WSManInstance –ResourceURI winrm/config/listener –Enumerate


#IPv4 Network Range
Set-Item -Path WSMan:\localhost\Service\IPv4Filter -Value 10.0.0.0-10.1.0.254
#IPv6 Block
Set-Item -Path WSMan:\localhost\Service\IPv6Filter -Value ""

#All WinRM filtering the settings seems to be okay, so we need to verify the WinRM firewall rules:

#Rule details
Get-NetFirewallRule *WINRM* | select name,enabled,profile,direction,action | ft
#Port details
Get-NetFirewallRule *WINRM* | Get-NetFirewallPortFilter | select instanceid,LocalPort
#Address details
Get-NetFirewallRule *WINRM* | Get-NetFirewallAddressFilter  | select InstanceID,RemoteAddress

New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "WINRM-HTTPS-In-TCP-ALL" `
-Profile Any -LocalPort 8888 -Direction Inbound -Protocol TCP -Action Allow `
-Description " Inbound rule for Windows Remote Management via WS-Management (HTTPS)*. [TCP 8888]" `
-RemoteAddress "10.0.0.0-10.1.0.254"

#########################################################################
#                        Inside Azure VM                                #
#                        EU DC - DCAZEU001                              #
#########################################################################

#Remoting into server From different server

#Test Connection - will fail becasue of no WINRM service certificate trusted
Enter-PSSession -ComputerName DCAZEU003.eu.adpstest.net -UseSSL -Port 8888 -Authentication Kerberos

#Copy WINRM service certificate to remote server
copy-item '\\dcazeu003\c$\temp\WinRMCert' C:\temp\winrmcert.crt

#Import WINRM service certificate to trusted root store (becasue we don't use PKI infrastrcuture)
Import-Certificate C:\temp\WinRMCert.crt -CertStoreLocation Cert:\LocalMachine\Root\

#Connect to server once again using PSSession
Enter-PSSession -ComputerName DCAZEU003.eu.adpstest.net -UseSSL -Port 8888 -Authentication Kerberos


