# This sample authenticates to Azure Active Directory (AAD) an obtains an access token.
# The access token can be used for authenticating to Business Central APIs.


# Parameters
$aadAppId = "a4ed4da1-6067-44ac-8501-5be9845adc44"        # partner's AAD app id
$aadAppRedirectUri = "http://localhost"                   # partner's AAD app redirect URI
$aadTenantId = "e359e991-afd5-488d-ac0a-5d2bd1df85f2"     # customer's tenant id

# Load Microsoft.IdentityModel.Clients.ActiveDirectory.dll
# Add-Type -Path "C:\Users\bojan.licen\Documents\WindowsPowerShell\Modules\AzureAD\2.0.2.130\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"  # Install-Module AzureAD to get this


# Load Microsoft.Identity.Client.dll
# Install-Package -Name Microsoft.Identity.Client -Source nuget.org -ProviderName nuget -SkipDependencies -Destination .\lib # run this line once to download the DLL
Add-Type -Path ".\lib\Microsoft.Identity.Client.4.21.0\lib\net461\Microsoft.Identity.Client.dll"
#Add-Type -Path ".\lib\Microsoft.Identity.Client.4.36.0\lib\Microsoft.Identity.Client.dll" # enable this line instead if you use PowerShell Core (pwsh)

# Get access token
$clientApplication = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($aadAppId).WithAuthority("https://login.microsoftonline.com/$aadTenantId").WithRedirectUri($aadAppRedirectUri).Build()
$authResult = $clientApplication.AcquireTokenInteractive([string[]]"https://api.businesscentral.dynamics.com/.default").ExecuteAsync().GetAwaiter().GetResult()
$accessToken = $authResult.AccessToken
Write-Host -ForegroundColor Cyan 'Authentication complete - we have an access token for Business Central, and it is stored in the $accessToken variable.'

# Peek inside the access token (this is just for education purposes; in actual API calls we'll just pass it as one long string)
$middlePart = $accessToken.Split('.')[1]
$middlePartPadded = "$middlePart$(''.PadLeft((4-$middlePart.Length%4)%4,'='))"
$middlePartDecoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($middlePartPadded))
$middlePartDecodedPretty = (ConvertTo-Json (ConvertFrom-Json $middlePartDecoded))
Write-Host "Contents of the access token:"
Write-Host $middlePartDecodedPretty




# Shared Parameters
#$accessToken = "" # get this from the Authenticate sample


# Get list of environments
$response = Invoke-WebRequest `
    -Method Get `
    -Uri    "https://api.businesscentral.dynamics.com/admin/v2.3/applications/businesscentral/environments" `
    -Headers @{Authorization=("Bearer $accessToken")}
Write-Host (ConvertTo-Json (ConvertFrom-Json $response.Content))
