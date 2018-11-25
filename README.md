# PCF on Azure the hard way -  installation instructions using nothing but the command line

Installation instructions for PCF on Azure without any UI interaction (well... you might have to authenticate your azure account). For standard evaluation purposes, use the PCF on Azure marketplace for a one-click installation: https://azuremarketplace.microsoft.com/en-us/marketplace/apps/pivotal.pivotal-cloud-foundry?tab=Overview. If you want to geek out or get a handle on how things are work internally, read on.

Install Azure CLI from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest

Clears previous cache of logins if needed:

`az account clear` 

`az cloud set --name AzureCloud`

Login

`az login`

Verify local cache of credentials
`az account list` 

Choose a location. I'll use eastus in the examples below.
LOCATION=eastus

Create resource group:

`az group create --name azure --location $LOCATION`

Create jumpbox VM
```
az vm create   \
--resource-group azure   \
--name jumpbox   \
--image UbuntuLTS   \
--admin-username azureuser   \
--data-disk-sizes-gb 200   \
--generate-ssh-keys   \
--vnet-address-prefix 192.168.0.0/16 \
--subnet-address-prefix 192.168.0.0/16 \
--private-ip-address 192.168.0.10  
```

Verify:
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

sudo apt-get install azure-cli && sudo apt --yes install unzip && sudo apt --yes install jq

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
PCF_DOMAIN_NAME=<redacted>        # buy one for cheap on domains.google (~10$ a year)
PCF_SUBDOMAIN_NAME=<redacted>     # az group list | jq -r .[0].name
PCF_OPSMAN_ADMIN_PASSWD=<choose secure admin password>

PCF_OPSMAN_FQDN=pcf.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}
USER_ID=<user> #change to match your user (odedia for example), this is for unique service account name creation
CLIENT_SECRET=<choose secure password>
DECRYPT_PHRASE=<choose secure key and save it safely! Your env is dead without this key!>
CREDHUB_KEY=<choose a secure key over 21 characters long>
NOTIFICATIONS_EMAIL=<your email>
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
--identifier-uris "http://${USER_ID}BOSHAzureCPI"
```

(Tip: if you ever need to delete the AAD use this: `az ad app delete --id "http://${USER_ID}BOSHAzureCPI"`)

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
Once confirmed, enable compute, netowrk and storage access:

```
az provider register --namespace Microsoft.Storage
az provider register --namespace Microsoft.Network
az provider register --namespace Microsoft.Compute
```

logout and login again to your regular azure account:

```
az logout
az login
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
L=Tel Aviv
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

Set variables for PAS installation from pivotal network. For example, using this URL https://network.pivotal.io/products/elastic-runtime/#/releases/220833 we can interpolate the following:
```
PRODUCT_SLUG="elastic-runtime"
RELEASE_ID="latest"
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
echo subscription_id       = \"`az account list | jq -r .[0].id`\" >> terraform.tfvars
echo tenant_id             = \"`az account list | jq -r .[0].tenantId`\" >> terraform.tfvars
echo client_id             = \"`az ad app show --id http://${USER_ID}BOSHAzureCPI | jq -r .appId`\" >> terraform.tfvars
echo client_secret         = \"${CLIENT_SECRET}\"  >> terraform.tfvars

echo env_name              = \"${PCF_SUBDOMAIN_NAME}\"   >> terraform.tfvars
echo location              = \"East US\" >> terraform.tfvars

RELEASE_JSON=$(curl \
    --fail \
    "https://network.pivotal.io/api/v2/products/ops-manager/releases/latest")

EULA_ACCEPTANCE_URL=$(echo ${RELEASE_JSON} |\
  jq -r '._links.eula_acceptance.href')

curl \
  --fail \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  --request POST \
  ${EULA_ACCEPTANCE_URL}


DOWNLOAD_ELEMENT=$(echo ${RELEASE_JSON} |\
  jq -r '.product_files[] | select(.aws_object_key | contains("onAzure.yml"))')

FILENAME=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '.aws_object_key | split("/") | last')

URL=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '._links.download.href')

curl \
  --fail \
  --location \
  --output ${FILENAME} \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  ${URL}

echo ops_manager_image_uri = \"`cat *onAzure.yml | grep east_us | sed 's/east_us: //'`\" >> terraform.tfvars
rm *onAzure.yml

echo dns_suffix            = \"${PCF_DOMAIN_NAME}\" >> terraform.tfvars
echo vm_admin_username     = \"admin\" >> terraform.tfvars
echo isolation_segment 	  = \"true\" >> terraform.tfvars
echo env_short_name = \"pcf${USER_ID}\" >> terraform.tfvars
```

Inspect `terraform.tfvars` to confirm the settings look ok.

Init terraform:

```
terraform init
terraform plan -out=plan
terraform apply --auto-approve
```

When terraform installation is complete, setup the DNS records in your google domain provider as type NS. Look at the `terraform output env_dns_zone_name_servers`. For example:

```
env_dns_zone_name_servers = [
    ns2-03.azure-dns.net.,
    ns3-03.azure-dns.org.,
    ns1-03.azure-dns.com.,
    ns4-03.azure-dns.info.
]
```

Set these records in google domains. The name should be your PCF_SUBDOMAIN_NAME. The type should be NS. the nameservers are taken from `env_dns_zone_name_servers`.

You will need to wait until the changes are propegated to your DNS provider. Use the following command to flush your local DNS cache (on macOS):

```
sudo killall -HUP mDNSResponder
```

Use the following command to query if your DNS entry is propegated:

```
nslookup
>set q=NS
>subdomain.domain.dom (change to your values to match $PCF_SUBDOMAIN_NAME.$PCF_DOMAIN_NAME)
```

Once there is a proper response for the above command, you can continue.

Configure opsman authentication using the om cli:

```
om \
  --target https://$PCF_OPSMAN_FQDN \
  --skip-ssl-validation \
    configure-authentication \
      --username admin \
      --password $PCF_OPSMAN_ADMIN_PASSWD \
      --decryption-passphrase $DECRYPT_PHRASE

```

You can go to the value of $PCF_OPSMAN_FQDN in your browser to see Ops Manager but we'll try to do everything from the command line.

Set the properties under BOSH director with the following loooooooooooooong command:

```

om --target https://$PCF_OPSMAN_FQDN --skip-ssl-validation --username admin --password $PCF_OPSMAN_ADMIN_PASSWD \
    configure-director \
      --director-configuration '{
        "ntp_servers_string": "us.pool.ntp.org",
        "resurrector_enabled": "true"
      }' \
      --iaas-configuration '{
        "subscription_id": "'"`terraform output subscription_id`"'",
        "tenant_id": "'"`terraform output tenant_id`"'",
        "client_id": "'"`terraform output client_id`"'",
        "client_secret": "'"${CLIENT_SECRET}"'",
        "resource_group_name": "'"`terraform output pcf_resource_group_name`"'",
        "bosh_storage_account_name": "'"`terraform output bosh_root_storage_account`"'",
        "ssh_public_key": "'"`terraform output ops_manager_ssh_public_key`"'",
        "ssh_private_key": '"`terraform output -json ops_manager_ssh_private_key | jq .value`"'
      }' \
      --networks-configuration "{
        \"icmp_checks_enabled\": false,
        \"networks\": [
          {
            \"name\": \"Management\",
            \"subnets\": [
              {
                \"iaas_identifier\": "\""`terraform output network_name`/`terraform output management_subnet_name`"\"",
                \"cidr\": "\""`terraform output management_subnet_cidrs`"\"",
                \"reserved_ip_ranges\": "\""`terraform output management_subnet_cidrs | awk -F . 'BEGIN {OFS="."} {print $1,$2,$3,$4+1"-"$1,$2,$3,$4+9}'`"\"",
                \"dns\": \"168.63.129.16\",
                \"gateway\": "\""`terraform output management_subnet_cidrs | awk -F . 'BEGIN {OFS="."} {print $1,$2,$3,$4+1}'`"\""
              }
            ]
          },
          {
            \"name\": \"PAS\",
            \"subnets\": [
              {
                \"iaas_identifier\": "\""`terraform output network_name`/`terraform output pas_subnet_name`"\"",
                \"cidr\": "\""`terraform output pas_subnet_cidrs`"\"",
                \"reserved_ip_ranges\": "\""`terraform output pas_subnet_cidrs | awk -F . 'BEGIN {OFS="."} {print $1,$2,$3,$4+1"-"$1,$2,$3,$4+9}'`"\"",
                \"dns\": \"168.63.129.16\",
                \"gateway\": "\""`terraform output pas_subnet_cidrs | awk -F . 'BEGIN {OFS="."} {print $1,$2,$3,$4+1}'`"\""
              }
            ]
          },
          {
            \"name\": \"Services\",
            \"service_network\": true,
            \"subnets\": [
              {
                \"iaas_identifier\": "\""`terraform output network_name`/`terraform output services_subnet_name`"\"",
                \"cidr\": "\""`terraform output services_subnet_cidrs`"\"",
                \"reserved_ip_ranges\": "\""`terraform output services_subnet_cidrs | awk -F . 'BEGIN {OFS="."} {print $1,$2,$3,$4+1"-"$1,$2,$3,$4+9}'`"\"",
                \"dns\": \"168.63.129.16\",
                \"gateway\": "\""`terraform output services_subnet_cidrs | awk -F . 'BEGIN {OFS="."} {print $1,$2,$3,$4+1}'`"\""
              }            
            ]
      }

    ]  
}" \
--network-assignment '{
  "network": {
    "name" : "Management"
  }
}' \
--resource-configuration '{
  "compilation" : {
    "instances": 8
  }
}'
```
You might want to review the changes in a browser (go to $PCF_OPSMAN_FQDN).

Apply changes. This will take about 10 minutes:
```
om --target https://$PCF_OPSMAN_FQDN --skip-ssl-validation --username admin --password $PCF_OPSMAN_ADMIN_PASSWD apply-changes
```

Create network peering from the jumpbox to the PCF network:

```
az network vnet peering create --name jumpbox-peering --remote-vnet azure-virtual-network --resource-group azure --vnet-name jumpboxVNET --allow-forwarded-traffic --allow-gateway-transit --allow-vnet-access

az network vnet peering create --name opsman-peering --remote-vnet jumpboxVNET --resource-group azure --vnet-name azure-virtual-network --allow-forwarded-traffic --allow-gateway-transit --allow-vnet-access


```

Export the BOSH environment variables:
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
Copy the root certificate to the jumpbox:

```
sudo mkdir -p /var/tempest/workspaces/default

sudo sh -c \
  "om \
    --skip-ssl-validation \
    --target ${PCF_OPSMAN_FQDN} \
    --username admin \
    --password ${PCF_OPSMAN_ADMIN_PASSWD} \
    curl \
      --silent \
      --path "/api/v0/security/root_ca_certificate" |
        jq --raw-output '.root_ca_certificate_pem' \
          > /var/tempest/workspaces/default/root_ca_certificate"

```

Verify connectivity:

```
bosh env
```

Check the BOSH tasks that were executed so far. Not many, yet.
```
bosh tasks --recent=30
```

Inspect the single task that was executed:
```
bosh task 1
```

Inspect the single task in debug mode:
```
bosh task 1 --debug
```

Installing PAS
--------------

Authenticate:

```
AUTHENTICATION_RESPONSE=$(curl \
  --fail \
  --data "{\"refresh_token\": \"${PCF_PIVNET_UAA_TOKEN}\"}" \
  https://network.pivotal.io/api/v2/authentication/access_tokens)
```

Get Token:
```
PIVNET_ACCESS_TOKEN=$(echo ${AUTHENTICATION_RESPONSE} | jq -r '.access_token')
```

Get the latest PAS:


```
cd ~

RELEASE_JSON=$(curl \
    --fail \
    "https://network.pivotal.io/api/v2/products/elastic-runtime/releases/latest")

EULA_ACCEPTANCE_URL=$(echo ${RELEASE_JSON} |\
  jq -r '._links.eula_acceptance.href')

curl \
  --fail \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  --request POST \
  ${EULA_ACCEPTANCE_URL}

```
For the Small Footprint installation, use the following:
```
DOWNLOAD_ELEMENT=$(echo ${RELEASE_JSON} |\
  jq -r '.product_files[] | select(.aws_object_key | contains("elastic-runtime/srt"))')
```

For the full PAS, use the following:
```
DOWNLOAD_ELEMENT=$(echo ${RELEASE_JSON} |\
  jq -r '.product_files[] | select(.aws_object_key | contains("elastic-runtime/cf-2"))')
```

Extract the download URL:
```
FILENAME=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '.aws_object_key | split("/") | last')

URL=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '._links.download.href')
```
Download the file:
```
curl \
  --fail \
  --location \
  --output ${FILENAME} \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  ${URL}
```

Upload the tile:

```
om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  upload-product \
    --product ${FILENAME}
```

Stage the tile:

```
PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  available-products \
    --format json)

VERSION=$(echo ${PRODUCTS} |\
  jq -r 'map(select(.name == "'cf'")) | first | .version')

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  stage-product \
    --product-name "cf" \
    --product-version ${VERSION}
```

Get Staged product GUID:

```
STAGED_PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products)

PRODUCT_GUID=$(echo ${STAGED_PRODUCTS} |\
  jq -r 'map(select(.type == "'cf'")) | first | .guid')
```

Find configurable properties:

```
PROPERTIES=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products/${PRODUCT_GUID}/properties)
    
```

Setup network settings:
```
NETWORK_SETTINGS_JSON=$(cat <<-EOF
{
  "singleton_availability_zone": {
    "name": "null"
  },
  "other_availability_zones": [
    {
      "name": "null"
    }
  ],
  "network": {
    "name": "PAS"
  }
}
EOF
)

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  configure-product \
    --product-name "cf" \
    --product-network "${NETWORK_SETTINGS_JSON}"
```

Setup other properties:

```
CERT_PEM=$(cat ~/${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.cert | awk '{printf "%s\\r\\n", $0}')
KEY_PEM=$(cat ~/${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.key | awk '{printf "%s\\r\\n", $0}')


PROPERTIES_JSON=$(cat <<-EOF
  {
   ".cloud_controller.system_domain": {
     "value": "sys.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}"
   },
   ".cloud_controller.apps_domain": {
     "value": "apps.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}"
   },
   ".properties.haproxy_forward_tls": {
     "value": "disable"
   },
   ".ha_proxy.skip_cert_verify": {
      "value": true
   },
   ".properties.security_acknowledgement": {
      "value": "X"
   },
   ".uaa.service_provider_key_credentials": {
      "value": {
        "private_key_pem": "${KEY_PEM}",
        "cert_pem": "${CERT_PEM}"
      }
   },
   ".properties.networking_poe_ssl_certs": {
      "value": [
        {
          "name": "default",
          "certificate": {
              "private_key_pem": "${KEY_PEM}",
              "cert_pem": "${CERT_PEM}"
          }
        }
      ]
    },
    ".properties.credhub_key_encryption_passwords": {
      "value": [
        {
          "name": "default",
          "provider": "internal",
          "key": {
            "secret": "${CREDHUB_KEY}"
          },
          "primary": true
        }
      ] 
    },
    ".mysql_monitor.recipient_email": {
      "value": "${NOTIFICATIONS_EMAIL}"
    }
  }
EOF
)

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  configure-product \
    --product-name "cf" \
    --product-properties "${PROPERTIES_JSON}"
```

Configure the resource jobs:

```
cd ./pivotal-cf-terraforming-azure-*/
cd terraforming-pas

JOBS_PROPERTIES=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products/${PRODUCT_GUID}/jobs)
    
JOB_GUID=`echo $JOBS_PROPERTIES | jq -r '.jobs[] | select(.name =="router")|.guid'`


om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products/${PRODUCT_GUID}/jobs/${JOB_GUID}/resource_config \
    -x PUT -d '{
          "instances": 1,
          "instance_type": {
            "id": "automatic"
          },
          "elb_names": ["'"${WEB_LB}"'"]
        }'


TCP_LB=`terraform output tcp_lb_name`
JOB_GUID=`echo $JOBS_PROPERTIES | jq -r '.jobs[] | select(.name =="tcp_router")|.guid'`

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products/${PRODUCT_GUID}/jobs/${JOB_GUID}/resource_config \
    -x PUT -d '{
          "instances": 1,
          "persistent_disk": {
            "size_mb": "automatic"
          },
          "instance_type": {
            "id": "automatic"
          },
          "elb_names": ["'"${TCP_LB}"'"]
        }'
        
        
DIEGO_LB=`terraform output diego_ssh_lb_name`
JOB_GUID=`echo $JOBS_PROPERTIES | jq -r '.jobs[] | select(.name =="control")|.guid'`

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products/${PRODUCT_GUID}/jobs/${JOB_GUID}/resource_config \
    -x PUT -d '{
          "instances": 1,
          "instance_type": {
            "id": "automatic"
          },
          "elb_names": ["'"${DIEGO_LB}"'"]
        }'
        
om --target https://$PCF_OPSMAN_FQDN --skip-ssl-validation --username admin --password $PCF_OPSMAN_ADMIN_PASSWD apply-changes
```

You can CTRL-C (break) the execution in the middle, the installation will continue. You can check the progress in https://$PCF_OPSMAN_FQDN

Inspect bosh tasks while installation is running:

```
bosh tasks --recent=30
```

Inspect the single task that was executed:
```
bosh task 20
```

Some tasks might output information about the Cloud Provider Interface (CPI):
```
bosh task 20 --cpi
```

Everything below is still a work in progress...
----------

Installing MySQL
--------

PRODUCT_SLUG="pivotal-mysql"
RELEASE_ID="latest"
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

Extract the download URL:

```
DOWNLOAD_ELEMENT=$(echo ${RELEASE_JSON} |\
  jq -r '.product_files[] | select(.aws_object_key | contains(".pivotal"))')

FILENAME=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '.aws_object_key | split("/") | last')

URL=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '._links.download.href')

curl \
  --fail \
  --location \
  --output ${FILENAME} \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  ${URL}
```

Upload the tile:

```
om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  upload-product \
    --product ${FILENAME}
```

Stage the tile:

```
PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  available-products \
    --format json)

VERSION=$(echo ${PRODUCTS} |\
  jq -r 'map(select(.name == "'pivotal-mysql'")) | first | .version')

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  stage-product \
    --product-name "pivotal-mysql" \
    --product-version ${VERSION}
```

Get Staged product GUID:

```
STAGED_PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products)

PRODUCT_GUID=$(echo ${STAGED_PRODUCTS} |\
  jq -r 'map(select(.type == "'pivotal-mysql'")) | first | .guid')
```



Installing Redis
--------
Get the release JSON for the PAS version you want to install:

```
  RELEASE_JSON=$(curl \
    --fail \
    "https://network.pivotal.io/api/v2/products/p-redis/releases/latest")
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

Extract the download URL:

```
DOWNLOAD_ELEMENT=$(echo ${RELEASE_JSON} |\
  jq -r '.product_files[] | select(.aws_object_key | contains(".pivotal"))')

FILENAME=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '.aws_object_key | split("/") | last')

URL=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '._links.download.href')

curl \
  --fail \
  --location \
  --output ${FILENAME} \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  ${URL}
```

Upload the tile:

```
om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  upload-product \
    --product ${FILENAME}
```

Stage the tile:

```
PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  available-products \
    --format json)

VERSION=$(echo ${PRODUCTS} |\
  jq -r 'map(select(.name == "'p-redis'")) | first | .version')

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  stage-product \
    --product-name "p-redis" \
    --product-version ${VERSION}
```

Get Staged product GUID:

```
STAGED_PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products)

PRODUCT_GUID=$(echo ${STAGED_PRODUCTS} |\
  jq -r 'map(select(.type == "'p-healthwatch'")) | first | .guid')


Installing Healthwatch
--------

Get the release JSON for the PAS version you want to install:

```
  RELEASE_JSON=$(curl \
    --fail \
    "https://network.pivotal.io/api/v2/products/p-healthwatch/releases/latest")
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

Extract the download URL:

```
DOWNLOAD_ELEMENT=$(echo ${RELEASE_JSON} |\
  jq -r '.product_files[] | select(.aws_object_key | contains(".pivotal"))')

FILENAME=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '.aws_object_key | split("/") | last')

URL=$(echo ${DOWNLOAD_ELEMENT} |\
  jq -r '._links.download.href')

curl \
  --fail \
  --location \
  --output ${FILENAME} \
  --header "Authorization: Bearer ${PIVNET_ACCESS_TOKEN}" \
  ${URL}
```

Upload the tile:

```
om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  upload-product \
    --product ${FILENAME}
```

Stage the tile:

```
PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  available-products \
    --format json)

VERSION=$(echo ${PRODUCTS} |\
  jq -r 'map(select(.name == "'p-healthwatch'")) | first | .version')

om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  stage-product \
    --product-name "p-healthwatch" \
    --product-version ${VERSION}
```

Get Staged product GUID:

```
STAGED_PRODUCTS=$(om \
  --username admin \
  --password ${PCF_OPSMAN_ADMIN_PASSWD} \
  --target ${PCF_OPSMAN_FQDN} \
  --skip-ssl-validation \
  curl \
    --path /api/v0/staged/products)

PRODUCT_GUID=$(echo ${STAGED_PRODUCTS} |\
  jq -r 'map(select(.type == "'p-healthwatch'")) | first | .guid')



