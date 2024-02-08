#############                 CHAPTER 4                    ##############
#########################################################################
#########################################################################
#                        Inside Azure VM    #1                          #
#                        ROOT DC - DCAZROOT001                          #
#########################################################################
#Verifying DNS Resolution of domains in the forest
Resolve-DnsName microsoft.com   -Server 10.0.0.5
Resolve-DnsName adpstest.net    -Server 10.0.0.5
Resolve-DnsName ap.adpstest.net -Server 10.0.0.5
Resolve-DnsName eu.adpstest.net -Server 10.0.0.5

#Creation of new Replication configuration for the forest 
New-ADReplicationSite -Name "WEEU01"
Set-ADReplicationSiteLink -Identity "DefaultIPSiteLink" -SitesIncluded @{Add="WEEU01";}
New-ADReplicationSite -Name "NEU01"
Set-ADReplicationSiteLink -Identity "DefaultIPSiteLink" -SitesIncluded @{Add="NEU01";}
New-ADReplicationSite -Name "CEIN01"
Set-ADReplicationSiteLink -Identity "DefaultIPSiteLink" -SitesIncluded @{Add="CEIN01";}

#Configuration of replication frequency:
Set-ADReplicationSiteLink -Identity "DefaultIPSiteLink" -ReplicationFrequencyInMinutes 15

#Creation of new AD Subnets and attaching them to the AD Sites
New-ADReplicationSubnet -Name "10.0.0.0/16" -Site WEEU01
New-ADReplicationSubnet -Name "10.1.0.0/16" -Site NEU01
New-ADReplicationSubnet -Name "10.2.0.0/16" -Site CEIN01

#Moving Domain Controllers configuration objects into proper AD Sites:
Move-ADDirectoryServer -Identity "DCAZROOT001" -Site "WEEU01"
Move-ADDirectoryServer -Identity "DCAZEU001"   -Site "WEEU01"
Move-ADDirectoryServer -Identity "DCAZEU002"   -Site "NEU01"
Move-ADDirectoryServer -Identity "DCAZAP001"   -Site "CEIN01"

#########################################################################
#                        Inside Azure VM    #2                          #
#                        CHILD DC - DCAZUEU002                          #
#########################################################################

#Moving the FSMO Role holders for the domain and forest

Move-ADDirectoryServerOperationMasterRole -Identity "DCAZUEU002" -OperationMasterRole PDCEmulator

#Sizing the role if nessesary - if the current FSMO role holder is not avaivable and will be not restored

Move-ADDirectoryServerOperationMasterRole -Identity "DCAZUEU002" -OperationMasterRole PDCEmulator -Force

#########################################################################
#                        Inside Azure VM    #1                          #
#                        ROOT DC - DCAZROOT001                          #
#########################################################################

#Modification of Default Domain Password Policy
Set-ADDefaultDomainPasswordPolicy -Identity adpstest.net -LockoutDuration 00:15:00 `
-LockoutObservationWindow 00:15:00 -ComplexityEnabled $True `
-ReversibleEncryptionEnabled $False -MaxPasswordAge 60.00:00:00

#Creation of new Organizational Unit Structure

New-ADOrganizationalUnit -Name Office -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name UK -Path "OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Workstations -Path  "OU=UK,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name StandardUsers -Path  "OU=UK,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name AdminUsers -Path  "OU=UK,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Groups -Path  "OU=UK,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name PL -Path "OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Workstations -Path  "OU=PL,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name StandardUsers -Path  "OU=PL,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name AdminUsers -Path  "OU=PL,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Groups -Path  "OU=PL,OU=Office,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name GlobalResources -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Delegation -Path "OU=GlobalResources,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Groups -Path "OU=GlobalResources,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name ServiceAccounts -Path "OU=GlobalResources,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Servers -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Application -Path "OU=Servers,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Infrastructure -Path "OU=Servers,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name Database -Path "OU=Servers,DC=ADPSTEST,DC=NET" -ProtectedFromAccidentalDeletion $true

#Delegation of the permissions for specific OUs

Set-Location AD:
$OrganizationalUnit = "OU=Workstations,OU=PL,OU=Office,DC=adpstest,DC=net"
$ACL = Get-Acl -Path $OrganizationalUnit
$DelegationGroup = Get-ADGroup "PL_Workstations"
$DelegationGroupSID = [System.Security.Principal.SecurityIdentifier] $DelegationGroup.SID
$GroupReference = [System.Security.Principal.IdentityReference] $DelegationGroupSID
$ComputersGUID = [GUID]"bf967a86-0de6-11d0-a285-00aa003049e2"
$RuleCreateAndDeleteComputers = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupReference, "CreateChild, DeleteChild", "Allow", $ComputersGUID, "All")
$RuleFullControllComputers    = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupReference, "GenericAll", "Allow", "Descendents",$ComputersGUID)
$ACL.AddAccessRule($RuleCreateAndDeleteComputers)
$ACL.AddAccessRule($RuleFullControllComputers)
Set-Acl -Path $OrganizationalUnit -AclObject $ACL

#Enabledment of AD Recycle Bin (cannot be reversed)
Enable-ADOptionalFeature ` 
-Identity 'CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=adpstest,DC=net' `
-Scope ForestOrConfigurationSet -Target 'adpstest.net'

#Verification of the Recycle Bin AD User restore
Get-ADUser -Name Test | Remove-ADUser
Get-ADObject -Name Test -IncludeDeletedObjects | Restore-ADObject

#Creation of Fine Grained Password Policy add assigment to Domain Admins
New-ADFineGrainedPasswordPolicy FGPP-DomainAdmins -ComplexityEnabled:$true -LockoutDuration:"00:30:00" `
-LockoutObservationWindow:"00:30:00" -LockoutThreshold:"5" -MaxPasswordAge:"30.00:00:00" `
-MinPasswordAge:"1.00:00:00" -MinPasswordLength:"15" -PasswordHistoryCount:"24" `
-Precedence:"1" -ReversibleEncryptionEnabled:$false -ProtectedFromAccidentalDeletion:$true
Add-ADFineGrainedPasswordPolicySubject FGPP-DomainAdmins -Subjects 'Domain Admins'

#Disabling the Default Admin Account in Domain:

$SIDDomain = ((Get-ADDomain).domainsid ).ToString()
$AdministratorSID = $SIDDomain + "-500"
$User = Get-ADUser -Identity $AdministratorSID
$User | Set-ADUser -Enabled $false
$User | Rename-ADObject -NewName adam_ad

#Migration of the Default Admin account and Domain Admin account into prepared OU structure
$SIDDomain = ((Get-ADDomain).domainsid ).ToString()
$AdministratorSID = $SIDDomain + "-500"
Get-ADUser -Identity $AdministratorSID | Move-ADObject -TargetPath "OU=Delegation,OU=GlobalResources,DC=ADPSTEST,DC=NET"
Get-ADUser -Identity adpsadmin | Move-ADObject -TargetPath "OU=Delegation,OU=GlobalResources,DC=ADPSTEST,DC=NET"

