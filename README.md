# PCF on Azure installation instructions
Installation instructions for PCF on Azure with as minimal UI interaction as possible.

Install Azure CLI from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest

`az cloud set --name AzureCloud`

`az clear` (clears previous cache of logins!)

`az login`

`az account list` Verifies local cache of credentials

`az group create --name pcf-azure --location eastus`

```
az vm create \
  --resource-group pcf-azure \
  --name jumpbox \
  --image UbuntuLTS \
  --admin-username azureuser \
  --data-disk-sizes-gb 200 \
  --generate-ssh-keys
  ```
  
  `az vm list`
  
  This one is a bit ridicilous but the only way I found to ssh dynamically into the jumpbox (pull-request a bettwer way, please!):
  
```
ssh azureuser@`az vm list-ip-addresses \
               -n jumpbox \
               --query [0].virtualMachine.network.publicIpAddresses[0].ipAddress \
               -o tsv`
```

