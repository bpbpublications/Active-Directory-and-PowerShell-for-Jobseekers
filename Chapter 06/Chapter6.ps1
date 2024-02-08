#############                 CHAPTER 6                    ##############
#########################################################################
#########################################################################
#                        Inside Azure VM    #1                          #
#                        ROOT DC - DCAZROOT001                          #
#########################################################################

#Creating new group in specific OU Path and domain 
New-ADGroup -Name "NetworkShare_Access_RW" -SamAccountName "NetworkShare_Access_RW" `
-GroupCategory Security -GroupScope Global -DisplayName "NetworkShare_Access_RW" `
-Path "OU=Groups,OU=GlobalResources,DC=adpstest,DC=net" -server adpstest.net

#Setting the group description
Set-ADGroup "NetworkShare_Access_RW" -Description "This Group provide access to Share XYZ on Application Server"

#Creation of AD group with description populated
New-ADGroup -Name "NetworkShare_Access_RW" -SamAccountName "NetworkShare_Access_RW" `
-GroupCategory Security -GroupScope Global -DisplayName "NetworkShare_Access_RW" `
-Path "OU=Groups,OU=GlobalResources,DC=adpstest,DC=net" -Description "This Group provide access to Share XYZ on Application Server"

#Setting the AD Group manager field
Set-ADGroup "NetworkShare_Access_RW" -ManagedBy "UK_Workstations"

#Removal of AD Group
Remove-ADGroup "Test_Orphaned_Sid"

#Adding group member 
Add-ADGroupMember "Backup Operators" -Members adpsadmin

#Removing group mamager 
Remove-ADGroupMember "Backup Operators" -Members adpsadmin

#Listing the group membership
Get-ADGroupMember "GroupName" # This command will report direct membership

#Listing the group membership recursevely 
Get-ADGroupMember "GroupName" -Recursive  #This command will report recursive members 

#################################################################################################################
# Add multiple users to single group
#################################################################################################################
# Create list of users as CSV file with first line header “name”
# Name
# UserTest1
# UserTest2
# UserTest3 
$Users = import-csv c:\temp\import.csv

Foreach ($User in $Users)
{
    # Quering global catalog
    # As some users could be provided from different
    # domain inside of the forest
    $User = Get-ADUser $User.Name -server adpstest.net:3268
    #
    # Pointing to standard port as global catalog is read only
    # Neet to point to domain that the group is placed in  
    # As some users could be provided from different
    # domain inside of the forest
    Add-ADGroupMember -Identity "PL_Workstations" -Members $User -server Adpstest.net:389 -Confirm:$false
    # Similar for removal
    Remove-ADGroupMember -Identity "PL_Workstations" -Members $User -server Adpstest.net:389 -Confirm:$false
}

#################################################################################################################
# Add user to mulitiple groups
################################################################################################################# 
#Create list of groups as CSV file with first line header “name” and “DistinguishedName” save as importGroups.csv without # characters
# “Name”,”DistinguishedName”
# “Schema Admins”, "CN=Schema Admins,CN=Users,DC=adpstest,DC=net”
# “Domain Admins”, “CN=Domain Admins,CN=Users,DC=adpstest,DC=net”
$Groups = import-csv c:\temp\importGroups.csv
Foreach ($Group in $Groups)
{
    # Quering global catalog
    # as some groups could be provided from different
    # domain inside of the forest
    $Group = Get-ADGroup $Group.Name -server adpstest.net:3268
    #
    # Pointing to standard port as global catalog is read only
    # Neet to point to domain that the user is placed in  
    Add-ADPrincipalGroupMembership -Identity 8a3ee9e8-b75f-445b-b9ed-78d9f344caa3 -MemberOf $Group.DistinguishedNAme  -Confirm:$false -server adpstest.net:389
    # Similar for removal
    Remove-ADPrincipalGroupMembership -Identity 8a3ee9e8-b75f-445b-b9ed-78d9f344caa3 -MemberOf $Group.DistinguishedNAme -Confirm:$false -server adpstest.net:389
}
#################################################################################################################
#Copy membership between two users

$UserToBeAdded  = Get-ADUser adpsadmin2   -pr memberof
$UserToCopy     = Get-ADUser adpsadmin     -pr memberof
$UserToCopy.MemberOf | Add-ADGroupMember -Members $UserToBeAdded

#################################################################################################################
#Clear membership of a user
$User  = Get-ADUser adpsadmin2   -pr memberof
$User.MemberOf | Remove-ADGroupMember -Members $User -Confirm:$false

#################################################################################################################
#Extract members of groups from static list
#################################################################################################################
$Groups = import-csv c:\temp\importGroups.csv
$Members=@()
Foreach ($Group in $Groups)
{
    # Quering non global catalog  as not every membership is whitin global catalog
    # Script would need to be executed for each domain in forest
    $GroupObject = Get-ADGroup $Group.Name -server adpstest.net
    $GroupMembers = Get-ADGroupMember $GroupObject
    foreach($Member in $GroupMembers)
    {
        #Creating Result object and adding specific fields to the results.
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -NotePropertyName "GroupName" -NotePropertyValue $GroupObject.Name
        $Result | Add-Member -NotePropertyName "GroupDistinguishedName" -NotePropertyValue $GroupObject.DistinguishedName
        $Result | Add-Member -NotePropertyName "UserName" -NotePropertyValue $Member.Name
        $Result | Add-Member -NotePropertyName "UserDistinguishedName" -NotePropertyValue $Member.DistinguishedName
        $Members+= $Result
    }
}
#In big environments showing the results is slowing the script execution
write-output $Members

#Append can be used when exporting data to same file from multiple executions
$Members | Export-CSV -Path C:\temp\exportMembership.csv #-Append

#################################################################################################################
#Extract members of protected groups in a domain
#################################################################################################################

$Groups = Get-ADGroup -filter 'adminCount -eq 1'
Foreach ($Group in $Groups)
{
    # Quering non global catalog  as not every membership is whitin global catalog
    # Script would need to be executed for each domain in forest
    $GroupMembers = Get-ADGroupMember $Group
    foreach($Member in $GroupMembers)
    {
        #Creating Result object and adding specific fields to the results.
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -NotePropertyName "GroupName" -NotePropertyValue $Group.Name
        $Result | Add-Member -NotePropertyName "GroupDistinguishedName" -NotePropertyValue $Group.DistinguishedName
        $Result | Add-Member -NotePropertyName "UserName" -NotePropertyValue $Member.Name
        $Result | Add-Member -NotePropertyName "UserDistinguishedName" -NotePropertyValue $Member.DistinguishedName
        $Members+= $Result
    } 
}

#In big environments showing the results is slowing the script execution
write-output $Members

#Append can be used when exporting data to same file from multiple executions
$Members | Export-CSV -Path C:\temp\exportMembership.csv #-Append


#################################################################################################################
#Extract members of protected groups in a forest
#################################################################################################################
#Get Forest Information
$Forest = Get-ADForest

#Perform operations for all domains
Foreach ($Domain in $Forest.Domains)
{
    $Groups = Get-ADGroup -filter 'adminCount -eq 1' -server $Domain
    Foreach ($Group in $Groups)
    {
        # Quering non global catalog  as not every membership is whitin global catalog
        # Script would need to be executed for each domain in forest
        $GroupMembers = Get-ADGroupMember $Group -Server $Domain
        foreach($Member in $GroupMembers)
        {
            #Creating Result object and adding specific fields to the results.
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -NotePropertyName "GroupName" -NotePropertyValue $Group.Name
            $Result | Add-Member -NotePropertyName "GroupDistinguishedName" -NotePropertyValue $Group.DistinguishedName
            $Result | Add-Member -NotePropertyName "UserName" -NotePropertyValue $Member.Name
            $Result | Add-Member -NotePropertyName "UserDistinguishedName" -NotePropertyValue $Member.DistinguishedName
            $Members+= $Result
        } 
    }
}
#In big environments showing the results is slowing the script execution
write-output $Members

#Append can be used when exporting data to same file from multiple executions
$Members | Export-CSV -Path C:\temp\exportMembership.csv #-Append

