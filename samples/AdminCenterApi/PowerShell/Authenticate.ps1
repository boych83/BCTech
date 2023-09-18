# This sample authenticates to Azure Active Directory (AAD) an obtains an access token.
# The access token can be used for authenticating to Business Central APIs.


# Parameters
$aadAppId = "c40d9a4c-8f00-4a28-aa5d-6a4d15ef161e"    # partner's AAD app id
$aadAppRedirectUri = "http://localhost"               # partner's AAD app redirect URI
$aadTenantId = "5f824385-5b14-483b-a1e3-d1ef07e79a25" # customer's tenant id
#https://businesscentral.dynamics.com/5f824385-5b14-483b-a1e3-d1ef07e79a25/Production

# Only needs to be done once: Install the MSAL PowerShell module (see https://github.com/AzureAD/MSAL.PS)
#Install-Module MSAL.PS

# Get access token
$msalToken = Get-MsalToken `
    -Authority "https://login.microsoftonline.com/$aadTenantId" `
    -ClientId $aadAppId `
    -RedirectUri $aadAppRedirectUri `
    -Scope "https://api.businesscentral.dynamics.com/.default"
$accessToken = $msalToken.AccessToken
Write-Host -ForegroundColor Cyan 'Authentication complete - we have an access token for Business Central, and it is stored in the $accessToken variable.'

# Peek inside the access token (this is just for education purposes; in actual API calls we'll just pass it as one long string)
$middlePart = $accessToken.Split('.')[1]
$middlePartPadded = "$middlePart$(''.PadLeft((4-$middlePart.Length%4)%4,'='))"
$middlePartDecoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($middlePartPadded))
$middlePartDecodedPretty = (ConvertTo-Json (ConvertFrom-Json $middlePartDecoded))
Write-Host "Contents of the access token:"
Write-Host $middlePartDecodedPretty







##########################################################################################
# Parameters
$aadAppId = "c40d9a4c-8f00-4a28-aa5d-6a4d15ef161e"        # partner's AAD app id
$aadAppRedirectUri = "http://localhost"                   # partner's AAD app redirect URI
$aadTenantId = "5f824385-5b14-483b-a1e3-d1ef07e79a25"     # customer's tenant id


# Load Microsoft.Identity.Client.dll
# Install-Package -Name Microsoft.Identity.Client -Source nuget.org -ProviderName nuget -SkipDependencies -Destination .\lib # run this line once to download the DLL
Add-Type -Path ".\lib\Microsoft.Identity.Client.4.41.0\lib\net461\Microsoft.Identity.Client.dll"
# Add-Type -Path ".\lib\Microsoft.Identity.Client.4.36.0\lib\netcoreapp2.1\Microsoft.Identity.Client.dll" # enable this line instead if you use PowerShell Core (pwsh)

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

#########################
# NEW
#########################
#########################
# PowerShell example
#########################
$aadTenantId  = "5f824385-5b14-483b-a1e3-d1ef07e79a25"     # customer's tenant id
$clientid     = "c40d9a4c-8f00-4a28-aa5d-6a4d15ef161e"
$clientsecret = "Uxv7Q~NXmBU_TcsiYCaAi6~eV6g8doTHRm1wX"
$scope        = "https://api.businesscentral.dynamics.com/.default"
$tenant       = "5f824385-5b14-483b-a1e3-d1ef07e79a25"
$environment  = "Sandbox"
$baseurl      = "https://api.businesscentral.dynamics.com/v2.0/$environment"
# Get access token
$body = @{grant_type="client_credentials";scope=$scope;client_id=$ClientID;client_secret=$ClientSecret}
$oauth = Invoke-RestMethod -Method Post -Uri $("https://login.microsoftonline.com/$tenant/oauth2/v2.0/token") -Body $body
# Get companies
$companies = Invoke-RestMethod `
             -Method Get `
             -Uri $("$baseurl/api/v2.0/companies") `
             -Headers @{Authorization='Bearer ' + $oauth.access_token}
$companyid = $companies.value[0].id
# Get customers
$customers = Invoke-RestMethod `
             -Method Get `
             -Uri $("$baseurl/api/v2.0/companies($companyid)/customers") `
             -Headers @{Authorization='Bearer ' + $oauth.access_token}

Install-Module -name MSAL.PS -Force -AcceptLicense



##############################
# PowerShell example with MSAL
##############################
$aadTenantId  = "e359e991-afd5-488d-ac0a-5d2bd1df85f2"     # customer's tenant id

$clientid     = "c40d9a4c-8f00-4a28-aa5d-6a4d15ef161e"
$clientsecret = "Uxv7Q~NXmBU_TcsiYCaAi6~eV6g8doTHRm1wX"
$scope        = "https://api.businesscentral.dynamics.com/.default"
$tenant       = "5f824385-5b14-483b-a1e3-d1ef07e79a25"
$environment  = "Production"
$environment  = "Release-21"
$baseurl      = "https://api.businesscentral.dynamics.com/v2.0/$environment"
# Get access token
$token = Get-MsalToken `
         -ClientId $clientid `
         -TenantId $tenant `
         -Scopes $scope `
         -ClientSecret (ConvertTo-SecureString -String $clientsecret -AsPlainText -Force)
# Get companies
$companies = Invoke-RestMethod `
             -Method Get `
             -Uri $("$baseurl/api/v2.0/companies") `
             -Headers @{Authorization='Bearer ' + $token.AccessToken}
$companies.value[0].id +'  Name:'+ $companies.value[0].name
# Get customers
$customers = Invoke-RestMethod `
             -Method Get `
             -Uri $("$baseurl/api/v2.0/companies($companyid)/customers") `
             -Headers @{Authorization='Bearer ' +  $token.AccessToken}

$customers.value[0].number





# Get list of environments
$response = Invoke-WebRequest `
    -Method Get `
    -Uri    "https://api.businesscentral.dynamics.com/admin/v2.9/applications/businesscentral/environments" `
    -Headers @{Authorization='Bearer ' +  $token.AccessToken}
Write-Host (ConvertTo-Json (ConvertFrom-Json $response.Content))


$response = Invoke-WebRequest `
-Method Get `
-Uri    "https://api.businesscentral.dynamics.com/admin/v2.8/applications/businesscentral/environments" `
-Headers @{Authorization='Bearer ' +  $token.AccessToken}

$response = Invoke-WebRequest `
-Method Get `
-Uri    "https://api.businesscentral.dynamics.com/environments/v1.1" `
-Headers @{Authorization='Bearer ' +  $token.AccessToken}


$environments = (ConvertFrom-Json $response.Content).Value
$environments | Select-Object -Property aadTenantId,name,type,applicationVersion,countryCode | Write-Output




Connect-AzAccount
$Password = ConvertTo-SecureString -String "7XWKJIFAGIF6" -AsPlainText -Force
$FilePath = "C:\Users\bojan.licen\Desktop\ErpServices\10395113-1.p12"
$VaultName = "myBC-KeyVault"

Import-AzKeyVaultCertificate -Name "TESTNO-PODJETJE-1512" -VaultName $VaultName -FilePath $FilePath -Password $Password 


$authContext = New-BcAuthContext -includeDeviceLogin
$environment = 'Release-21'
$AppIdHash = @{
    "AppName1" = "AppId1"
    "AppName2" = "AppId2"
}
$AppIdHash.GetEnumerator() | ForEach-Object { 
    $appId = $_.value
    Install-BcAppFromAppSource -bcAuthContext $authContext -AppId $appId -environment $environment -acceptIsvEula -installOrUpdateNeededDependencies
}