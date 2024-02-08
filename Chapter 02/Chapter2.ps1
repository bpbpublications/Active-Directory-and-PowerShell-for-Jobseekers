##########                 CHAPTER 2                    ###########
###################################################################
#         Create Cloud Shell or use Az modules o connect          #
###################################################################
#      If not in Cloud Shell, install and connect to Azure:
###################################################################
#Install-Module -Name Az -Repository PSGallery -Force
#Import-module AZ
#Connect-AzAccount
###################################################################

#List all avaivable subscriptions avaivable for connected users
Get-AZSubscription

#Select the specific subscription that you would like to manage
Select-AzSubscription ADPowershellAzure

#Create Resource Group
New-AzResourceGroup -Location WestEurope -Name Res-Group-Dev-ADTest

#Check available Azure regions 
Get-AzLocation | select name,displayname,location,type

#Create the Server from Captured template during manual installation
$Password=Read-host -MaskInput    
az deployment group create  --resource-group Res-Group-Dev-ADTest `
--template-file template.json  --parameters parameters.json `
--parameters adminPassword=$Password
