#!/bin/bash

check_and_update_secret() {  
    echo "Checking for expiring or expired secrets..."  
    secretEndDate=$(az ad app credential list --id "$2" -o tsv --query "[0].endDateTime")  
    # Convert date to Unix timestamp  
    secretEndDateTimestamp=$(date -d"$secretEndDate" +%s) 
    echo "Secret End Date: $secretEndDate" 
    threeMonthsLater=$(date -d "3 months" +%s) 
  
    if [ "$secretEndDateTimestamp" -le "$threeMonthsLater" ]; then   
        echo "The secret has expired or is about to expire."  
        read -p "Do you want to update the secret? (y/N): " response  
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then  
            echo "Updating the secret..."
        # Reset the application credential  
            newSecret=$(az ad app credential reset --id "$2" --years "2" --query "password" -o tsv --display-name "$1")  
            echo $newSecret
            if [ -n "$3" ]; then
                # Store the new secret in Azure KeyVault  
                echo "Updating Keyvault $3 for secret $1"
                az keyvault secret set --name "$1" --vault-name "$3" --value "$newSecret" 
                if [ $? -ne 0 ]; then  
                    echo "Error: Failed to update the secret in Azure KeyVault. Please check the KeyVault name and permissions." 
                    echo "Please manually add the following to KeyVault $newSecret" 
                    return 1  
                fi  
            else
        echo "No KeyVault was provided, please update manually" 
            fi
        else  
            echo "Update cancelled by user." 
        fi
    else  
        echo "The secret is not expired or about to expire. No action needed."  
    fi  
}  

# Function to create the Azure AD application registration
create_app_registration() {
    echo "Creating App Registration..."
    # Check if the app already exists
    existing_app=$(az ad app list --display-name "$1" --query "[].appId" -o tsv)

    if [[ -n $existing_app ]]; then
       echo "The app already exists. $existing_app"
       check_and_update_secret "$1" "$existing_app" "$3" 
       exit 1
    fi

    az ad app create --display-name "$1" --web-redirect-uris "$2" --sign-in-audience "AzureADMyOrg"
    sleep 5
}

create_app_service_principal() {
    echo "Creating Service Principal..."
    SERVICE_PRINCIPAL_ID=$(az ad sp create --id "$1")
    echo "Service Principal ID: ${SERVICE_PRINCIPAL_ID}"
    az ad sp update --id $1 --set 'tags=["WindowsAzureActiveDirectoryIntegratedApp"]'
    sleep 5
}

# Function to add application permissions
add_application_permissions() {
    echo "Adding Application permissions..."
    sleep 5
    az ad app permission add --id "$1" --api "00000003-0000-0000-c000-000000000000" --api-permissions "$2=Role"
}

# Function to add delegated permissions
add_delegated_permissions() {
    echo "Adding Delegated permissions..."
    az ad app permission add --id "$1" --api "00000003-0000-0000-c000-000000000000" --api-permissions "$2=Scope"
}

# Function to update the Azure AD application optional claims
update_application() {
    echo "Updating application with optional claims for in manifest.json..."
    #az ad app update --id "$1" --set "optionalClaims.idToken=[$2]" "optionalClaims.accessToken=[$3]" "optionalClaims.saml2Token=[$4]"
    az ad app update --id "$1" --optional-claims @manifest.json
}

# Function to store the client secret in Azure Key Vault
store_secret_in_keyvault() {
    echo "Storing Secret in KeyVault $2..."
    az keyvault secret set --name "$1" --vault-name "$2" --value "$3"
    return 0
}

# Parse command-line arguments
while getopts ":n:r:k:" opt; do
    case $opt in
        n)
            applicationName=$OPTARG
            ;;
        r)
            #IFS=',' read -ra redirectUris <<< "$OPTARG"
            redirectUris=$OPTARG
            ;;
        k)
            keyVaultName=$OPTARG
            useKeyVault=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            exit 1
            ;;
    esac
done

# Check if required command-line arguments are provided
if [ -z "$applicationName" ] || [ ${#redirectUris[@]} -eq 0 ]; then
    echo "Usage: $0 -n <applicationName> -r \"<redirectUri1> <redirectUri2> ...\" [-k <keyVaultName>]"
    exit 1
fi

echo "Application Name: $applicationName"
echo "Redirect URI: ${redirectUris}"

# Create the Azure AD application registration
create_app_registration "$applicationName" "$(echo "$redirectUris" | awk '{print $1}')" "$keyVaultName"

# Retrieve the application registration details
appRegistration=$(az ad app list --display-name "$applicationName" --query "[0]")

# Get the application ID
applicationId=$(echo "$appRegistration" | jq -r '.appId')

objectId=$(echo "$appRegistration" | jq -r '.id')

# Add application permissions
add_application_permissions "$applicationId" "5b567255-7703-4780-807c-7be8301ae99b"

# Add delegated permissions
add_delegated_permissions "$applicationId" "14dad69e-099b-42c9-810b-d002981feec1"    # offline_access
add_delegated_permissions "$applicationId" "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"    # profile
add_delegated_permissions "$applicationId" "e1fe6dd8-ba31-4d61-89e7-88639da4683d"    # User.Read

# Update the Azure AD application optional claims
update_application "$applicationId" 
echo "$applicationId"
echo "$objectId"

az ad app credential reset --id "$applicationId"

echo "Generate the application secret"

secret=$(az ad app credential reset --id "$applicationId" --years "2" --query "password" -o tsv --display-name "$applicationName")

az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$objectId" --headers "Content-Type=application/json" --body '{"api":{"acceptMappedClaims": "true"}}'

#Create Enterprise App
create_app_service_principal "$applicationId"

az ad app update --id $applicationId --web-redirect-uris ${redirectUris}

if [ "$useKeyVault" = true ]; then
    
    writekey=$(store_secret_in_keyvault "$applicationName" "$keyVaultName" "$secret")

    if [ "$writekey" ]; then
        echo "Successfully stored the secret in Azure Key Vault."
    else
        echo "Failed to store the secret in Azure Key Vault. Terminating..."
    fi

fi

