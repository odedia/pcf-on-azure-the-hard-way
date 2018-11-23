# PCF on Azure installation instructions
Installation instructions for PCF on Azure with as minimal UI interaction as possible.

Install Azure CLI from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest

`az clear` (clears previous cache of logins!)

`az cloud set --name AzureCloud`

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
  
  This one is a bit ridicilous but the only way I found to ssh dynamically into the jumpbox (pull-request a better way, please!):
  
```
ssh azureuser@`az vm list-ip-addresses \
               -n jumpbox \
               --query [0].virtualMachine.network.publicIpAddresses[0].ipAddress \
               -o tsv`
```

Tip: if you want to connect from another machine, you will need to copy the ssh keys from the original machine to the new machine. The keys must be protected with 0600 unix permissions:

```
sudo chmod 600 ~/.ssh/id_rsa         
sudo chmod 600 ~/.ssh/id_rsa.pub    
```

Usually the key is under ~/.ssh/id_rsa and ~/.ssh/id_rsa.pub but you can use other file names. For example, if the name of the key pair is azure and azure.pub you can connect with the following command:

```
ssh -i ~/.ssh/azure azureuser@`az vm list-ip-addresses \
               -n jumpbox \
               --query [0].virtualMachine.network.publicIpAddresses[0].ipAddress \
               -o tsv`
```

From now on - all activites are done on the remote jumpbox.
-------------------------------


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

PCF_PROJECT_ID=<redacted>         #get using: az group list | jq -r .[0].name
PCF_OPSMAN_FQDN=pcf.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}
USER_ID=<user> #change to match your user, this is for unique service account name creation
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

Make sure the account is valid by logging in to the AAD:

```
az login \
--username `az ad app show --id http://${USER_ID}BOSHAzureCPI | jq -r .appId` \
--password $CLIENT_SECRET \
--service-principal \
--tenant `az account list | jq -r .[0].tenantId`
```
Once confirmed, logout and login again to your regular azure account:

```
az logout
az login
```

Register compute, network and storage access:

```
az provider register --namespace Microsoft.Storage
az provider register --namespace Microsoft.Network
az provider register --namespace Microsoft.Compute
```

Create a self-signed certificate for installation:

```
cat > ./${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.cnf <<-EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C=IL
ST=Israel
L=Beer Sheca
O=Oded Shopen
OU=DEMO
CN = ${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = *.sys.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}
DNS.2 = *.login.sys.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}
DNS.3 = *.uaa.sys.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}
DNS.4 = *.apps.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}
EOF
```

Generate the key:

```
openssl req -x509 \
  -newkey rsa:2048 \
  -nodes \
  -keyout ${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.key \
  -out ${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.cert \
  -config ./${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.cnf
```

Set variables from pivotal network. For example, using this URL https://network.pivotal.io/products/elastic-runtime/#/releases/220833 we can interpolate the following:
```
PRODUCT_SLUG="elastic-runtime"
RELEASE_ID="220833"
```
Authenticate with Pivnet:

```
AUTHENTICATION_RESPONSE=$(curl \
  --fail \
  --data "{\"refresh_token\": \"${PCF_PIVNET_UAA_TOKEN}\"}" \
  https://network.pivotal.io/api/v2/authentication/access_tokens)
```

Get the access token:

`PIVNET_ACCESS_TOKEN=$(echo ${AUTHENTICATION_RESPONSE} | jq -r '.access_token')`

Get the release JSON for the PAS version you want to install:

```
  RELEASE_JSON=$(curl \
    --fail \
    "https://network.pivotal.io/api/v2/products/${PRODUCT_SLUG}/releases/${RELEASE_ID}")
```

Accept EULA:

```
EULA_ACCEPTANCE_URL=$(echo ${RELEASE_JSON} |\
  jq -r '._links.eula_acceptance.href')

curl \
  --fail \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  --request POST \
  ${EULA_ACCEPTANCE_URL}

```

Extract the terraform download URL for azure:

```
DOWNLOAD_ELEMENT=$(echo ${RELEASE_JSON} |\
  jq -r '.product_files[] | select(.aws_object_key | contains("terraforming-azure"))')

FILENAME=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '.aws_object_key | split("/") | last')

URL=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '._links.download.href')

```

Download and unzip:

```
curl \
  --fail \
  --location \
  --output ${FILENAME} \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  ${URL}
unzip ./${FILENAME}
cd ./pivotal-cf-terraforming-azure-*/
cd terraforming-pas
```

Create tfvars file:

```
touch terraform.tfvars
```

Edit the terraform file with the following parameters:

```
subscription_id       = "<1>"
tenant_id             = "<2>"
client_id             = "<3>"
client_secret         = "<4>"

env_name              = "pcf"
location              = "East US"
ops_manager_image_uri = "<5>"
dns_suffix            = "<6>"
vm_admin_username     = "admin"
isolation_segment 	  = "<7>"
```

The numbers above correspond to the following:

1. `az account list | jq -r .[0].id`
2. `az account list | jq -r .[0].tenantId`
3. `az ad app show --id http://${USER_ID}BOSHAzureCPI | jq -r .appId`
4. $CLIENT_SECRET
5. Get the download link from the Azure PDF at this link "Pivotal Cloud Foundry Ops Manager for Azure": https://network.pivotal.io/products/ops-manager/
6. your domain name (like example.com). I strongly recommend you'll register your own domain at https://domains.google
7. If you need isolation segments for your installation, set to true, otherwise false.

Init terraform:

```
terraform init
terraform plan -out=plan  #provide a UNIQUE env short name value, otherwise storage accounts creation might fail. for example pcfodedia
terraform apply plan
```

When terraform installation is complete, setup the DNS records in your google domain provider as type NS. Look at the terraform output and find the section for env_dns_zone_name_servers. For example:

```
env_dns_zone_name_servers = [
    ns2-03.azure-dns.net.,
    ns3-03.azure-dns.org.,
    ns1-03.azure-dns.com.,
    ns4-03.azure-dns.info.
]
```

Set these records in google domains. The name should be your PCF_SUBDOMAIN_NAME. The type should be NS. the nameservers are taken from env_dns_zone_name_servers.

You will need to wait until the changes are propegated to your DNS provider. Use the following command to flush your local DNS cache (on macOS):

```
sudo killall -HUP mDNSResponder
```

Use the following command to query if your DNS entry is propegated:

```
nslookup
>set q=NS
>subdomain.domain.dom
```

Once there is a proper response for the above command, you can continue.

Go to the value of $PCF_OPSMAN_FQDN and go to that URL in your browser.

Choose internal authentication.

username - admin
password - the value of $PCF_OPSMAN_ADMIN_PASSWD
decryption key = choose a secure key, and SAVE IT IN A SECURE LOCATION! your environment is dead without this key.


Set the properties under "Azure Config" as follows:

Subscription ID:  `az account list | jq -r .[0].id`
Tenant ID: `az account list | jq -r .[0].tenantId`
Application ID: `az ad app show --id http://${USER_ID}BOSHAzureCPI | jq -r .appId`
Client Secret: value of $CLIENT_SECRET
Resource Group Name: value of `terraform output | grep pcf_resource_group_name`
BOSH Storage Account Name: value of `terraform output | grep bosh_root_storage_account`
Default Security Group: value of `terraform output | grep bosh_deployed_vms_security_group_name`
SSH Public key: value of `terraform output | grep ops_manager_ssh_public_key`
SSH Private key: value of `terraform output` (search for ops_manager_ssh_private_key and copy entire multiline entry)


Set the properties for "Director Config" as follows:

NTP Server: `time.google.com`
BOSH Ressurector: enabled

For Create Networks, do the following:

Create new network for "Management"

Name: Management

NETWORK_NAME --> `terraform output | grep network_name`
SUBNET_NAME --> `terraform output | grep management_subnet_name`
CIDR --> `terraform output | grep management_subnet_cidrs` (might not show due to grep, scan output if this is the case)

Azure Network Name: NETWORK_NAME/SUBNET_NAME
CIDR: from above
Reserved IP Ranges: First 9 IPs, like 10.0.8.1-10.0.8.9
DNS: 168.63.129.16
Gateway: First IP, 10.0.8.1

Create new network for "PAS"

Name: PAS

NETWORK_NAME --> `terraform output | grep network_name`
SUBNET_NAME --> `terraform output | grep pas_subnet_name`
CIDR --> `terraform output | grep pas_subnet_cidrs` (might not show due to grep, scan output if this is the case)

Azure Network Name: NETWORK_NAME/SUBNET_NAME
CIDR: from above
Reserved IP Ranges: First 9 IPs, like 10.0.0.1-10.0.0.9
DNS: 168.63.129.16
Gateway: First IP, like 10.0.0.1


Create new network for "Services"

Name: Services

NETWORK_NAME --> `terraform output | grep network_name`
SUBNET_NAME --> `terraform output | grep services_subnet_name`
CIDR --> `terraform output | grep services_subnet_cidrs` (might not show due to grep, scan output if this is the case)

Azure Network Name: NETWORK_NAME/SUBNET_NAME
CIDR: from above
Reserved IP Ranges: First 9 IPs, like 10.0.4.1-10.0.4.9
DNS: 168.63.129.16
Gateway: First IP, like 10.0.4.1

Under "Assign Networks", select "Management" from the drop down.

Under "Security", paste the value of the certificate we created in line 163 (the contents of the file ending with .cert):

```
-----BEGIN CERTIFICATE-----
MIIDXjCCAkYCCQD7GjFMvGajMDANBgkqhkiG9w0BAQsFADBxMQswCQYDVQQGEwJJ
TDEPMA0GA1UECAwGSXNyYWVsMRMwEQYDVQQHDApCZWVyIFNoZWNhMRQwEgYDV...
-----END CERTIFICATE-----
```

Under Resource Config, change Master Compilation Job to 8 (for faster compilation).

On main screen, click Apply Changes

While installation continues, you can add the following command to your .bashrc file (at the end!)

```
export $( \
  om \
    --skip-ssl-validation \
    --target ${PCF_OPSMAN_FQDN} \
    --username admin \
    --password ${PCF_OPSMAN_ADMIN_PASSWD} \
    curl \
      --silent \
      --path /api/v0/deployed/director/credentials/bosh_commandline_credentials | \
        jq --raw-output '.credential' \
)
```

This will allow you to communicate with the BOSH director that is now being deployed.

