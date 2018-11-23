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

Install azure cli and other tools on remote jumpbox:

```
sudo apt-get install apt-transport-https lsb-release software-properties-common -y
AZ_REPO=$(lsb_release -cs)
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" | \
    sudo tee /etc/apt/sources.list.d/azure-cli.list

sudo apt-key --keyring /etc/apt/trusted.gpg.d/Microsoft.gpg adv \
     --keyserver packages.microsoft.com \
     --recv-keys BC528686B50D79E339D3721CEB3E94ADBE1229CF

sudo apt-get update
sudo apt-get install azure-cli
sudo apt --yes install unzip
sudo apt --yes install jq
wget -O terraform.zip https://releases.hashicorp.com/terraform/0.11.8/terraform_0.11.8_linux_amd64.zip && \
  unzip terraform.zip && \
  sudo mv terraform /usr/local/bin
wget -O om https://github.com/pivotal-cf/om/releases/download/0.41.0/om-linux && \
  chmod +x om && \
  sudo mv om /usr/local/bin/
wget -O bosh https://s3.amazonaws.com/bosh-cli-artifacts/bosh-cli-5.3.1-linux-amd64 && \
  chmod +x bosh && \
  sudo mv bosh /usr/local/bin/
wget -O /tmp/bbr.tar https://github.com/cloudfoundry-incubator/bosh-backup-and-restore/releases/download/v1.2.8/bbr-1.2.8.tar && \
  tar xvC /tmp/ -f /tmp/bbr.tar && \
  sudo mv /tmp/releases/bbr /usr/local/bin/

```
`az login`

create .env file:

```

PCF_PIVNET_UAA_TOKEN=<redacted>   # see https://network.pivotal.io/users/dashboard/edit-profile
PCF_DOMAIN_NAME=<redacted>        # e.g. example.com
PCF_SUBDOMAIN_NAME=pcf
PCF_OPSMAN_ADMIN_PASSWD=<choose secure admin password>

PCF_PROJECT_ID=$(az group list | jq -r .[0].name)
PCF_OPSMAN_FQDN=pcf.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}
USER_ID=odedia #change to match your user, this is for unique service account name creation
CLIENT_SECRET=<choose secure password>
```
source the .env file and add to the env of .bashrc:

```
source ~/.env
echo "source ~/.env" >> ~/.bashrc
```
Create an Azure Active Directory application (AAD) for BOSH:

```
az ad app create \
--display-name "Service Principal for BOSH" \
--password $CLIENT_SECRET \
--homepage "http://BOSHAzureCPI" \
--identifier-uris "http://${USER_ID}BOSHAzureCPI"```
```

(Tip: if you even need to delete the AAD use this: `az ad app delete --id "http://${USER_ID}BOSHAzureCPI"`)

Create a service principal from the AAD:

```
az ad sp create --id `az ad app show --id http://${USER_ID}BOSHAzureCPI | jq -r .appId`
```

Add the contributor role:

```
az role assignment create --assignee http://${USER_ID}BOSHAzureCPI --role "Contributor" --scope /subscriptions/`az account list | jq -r .[0].id`
```

Verify role assignment with this command:

```
az role assignment list --assignee "http://${USER_ID}BOSHAzureCPI"
```

Login to the AAD:

```
az login \
--username `az ad app show --id http://${USER_ID}BOSHAzureCPI | jq -r .appId` \
--password $CLIENT_SECRET \
--service-principal \
--tenant `az account list | jq -r .[0].tenantId`
```

Register compute, network and storage access:

```
az provider register --namespace Microsoft.Storage
az provider register --namespace Microsoft.Network
az provider register --namespace Microsoft.Compute
```
