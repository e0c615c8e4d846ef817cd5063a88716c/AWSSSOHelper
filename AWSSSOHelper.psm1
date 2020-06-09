#Requires -PSEdition Core

<#
.SYNOPSIS
This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.  Access tokens are cached locally to prevent the need to be pushed to a web browser each time you invoke the script (this is similar behaviour to aws cli v2).
.DESCRIPTION
This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.  Access tokens are cached locally to prevent the need to be pushed to a web browser each time you invoke the script (this is similar behaviour to aws cli v2).

Main usability enhancement compared to aws cli 2 is the abillity to specify the -AllRoleCredentials switch and retrieve all credentials for all accounts that you have access to.  You will be prompted to select a role where you have access to multiple roles for an account, alternatively you can specify a role by using the -RoleName parameter.
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start"
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles
.EXAMPLE
    $RoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -PassThru
    Get-S3Bucket @RoleCredentials
.EXAMPLE
    $AllRoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles
    $AllRoleCredentials | Foreach-Object { Get-S3Bucket -AccessKey $_.AccessKey -SecretKey $_.SecretKey -SessionToken $_.SessionToken }
.INPUTS
    StartUrl (Mandatory)
.OUTPUTS
    AccountId, RoleName, AccessKey, Expiration, SecretKey, SessionToken
.NOTES
    General notes
.COMPONENT
    The component this cmdlet belongs to
.ROLE
    The role this cmdlet belongs to
.FUNCTIONALITY
    The functionality that best describes this cmdlet
#>

function Get-AWSSSORoleCredential {
    param(
        [Parameter(Mandatory=$true)][string]$StartUrl,
        [string]$AccountId,
        [string]$RoleName,
        [switch]$AllAccountRoles,
        [switch]$RefreshAccessToken,
        [string]$Region,
        [switch]$PassThru,
        [string]$ClientName = "default",
        [ValidateSet('public')][string]$ClientType = "public",
        [int]$TimeoutInSeconds = 120,
        [string]$Path = (Join-Path $Home ".awsssohelper")
    )

    # Manually import the AWSPowerShell.NetCore module if present as it is not configured for auto-loading
    $awsNetCorePowerShellModuleName = 'AWSPowerShell.NetCore'
    if (Get-Module -Name $awsNetCorePowerShellModuleName -ListAvailable)
    {
        Import-Module -Name $awsNetCorePowerShellModuleName
    }

    if ($Region) {
        Set-DefaultAWSRegion $Region
    }
    elseif (($null -eq (Get-DefaultAWSRegion).Region)) {
        throw "No default AWS region configured, specify '-Region <region>' parameter or configure defaults using 'Set-DefaultAWSRegion'."
    }
    else {
        $Region = (Get-DefaultAWSRegion).Region
    }

    $CachePath = Join-Path $Path $ClientName

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }

    if (Test-Path $CachePath) {
        $AccessToken = Get-Content $CachePath -ErrorAction SilentlyContinue | ConvertFrom-Json
        try {
            Get-SSOAccountList -AccessToken $AccessToken.AccessToken  -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) | Out-Null
        }
        catch {
            Write-Host "Cached access token is no longer valid, will need to obtain via SSO."
            $RefreshAccessToken = $true
        }
    }

    if (!$AccessToken) {
        $RefreshAccessToken = $true
    }
    elseif ((New-TimeSpan $AccessToken.LoggedAt (Get-Date)).TotalMinutes -gt $AccessToken.ExpiresIn) {
        $RefreshAccessToken = $true
        Clear-Variable AccessToken
    }

    if ($RefreshAccessToken) {

        $Client = Register-SSOOIDCClient -ClientName $ClientName -ClientType $ClientType -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
        $DeviceAuth = Start-SSOOIDCDeviceAuthorization -ClientId $Client.ClientId -ClientSecret $Client.ClientSecret -StartUrl $StartUrl -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())

        try {
            $Process = Start-Process $DeviceAuth.VerificationUriComplete -PassThru
        }
        catch {
            continue
        }

        if (!$Process.Id) {
            Write-Host "`r`nVisit the following URL to authorise this session:`r`n"
            Write-Host -ForegroundColor White "$($DeviceAuth.VerificationUriComplete)`r`n"
        }
        
        Clear-Variable AccessToken -ErrorAction SilentlyContinue
        Write-Host "Waiting for SSO login via browser..."
        $SSOStart = Get-Date
        
        while (!$AccessToken -and ((New-TimeSpan $SSOStart (Get-Date)).TotalSeconds -lt $TimeoutInSeconds)) {
            try {
                $AccessToken = New-SSOOIDCToken -ClientId $Client.ClientId -ClientSecret $Client.ClientSecret -Code $DeviceAuth.Code -DeviceCode $DeviceAuth.DeviceCode -GrantType "urn:ietf:params:oauth:grant-type:device_code" -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
            }
            catch {
                # Write-Host $_.Exception.GetType().FullName, $_.Exception.Message
                Start-Sleep -Seconds 5
            }
        }
        if (!$AccessToken) {
            throw 'No access token obtained, exiting.'
        }
        
        $AccessToken | ConvertTo-Json | Set-Content $CachePath

    }

    if (!$AccountId) {
        try {
            $AWSAccounts = Get-SSOAccountList -AccessToken $AccessToken.AccessToken  -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
        }
        catch {
            throw "Error obtaining account list, access token is invalid.  Try running the command again with '-RefreshAccessToken' parameter."
        }
        if (!$AllAccountRoles) {
            $AccountIds = ($AWSAccounts | Sort-Object AccountName | Out-GridView -PassThru -Title "Select AWS Account").AccountId
        }
        else {
            $AccountIds = $AWSAccounts | Select-Object -ExpandProperty AccountId
        }
    }
    else {
        $AccountIds = $AccountId
    }

    $AccountIds | ForEach-Object { GetAccountRoleCredential -AccountId $_ -AccessToken $AccessToken.AccessToken -RoleName $RoleName -AllAccountRoles:$AllAccountRoles }

}

function GetAccountRoleCredential {
    param(
        [string]$AccountId,
        [string]$AccessToken,
        [string]$RoleName,
        [string]$Region,
        [switch]$AllAccountRoles
    )

    $Credentials = @()

    if (!$RoleName) {
        $SSORoles = Get-SSOAccountRoleList -AccessToken $AccessToken -AccountId $AccountId -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
        if ($SSORoles.Count -eq 1) {
            $AccountRoles = ($SSORoles | Select-Object -First 1).RoleName
        }
        elseif (!$AllAccountRoles) {
            $AccountRoles = ($SSORoles | Out-GridView -PassThru -Title "Select AWS SSO Role").RoleName
        }
        else {
            $AccountRoles = $SSORoles.RoleName
        }
    }
    else {
        $AccountRoles = $RoleName
    }

    foreach ($role in $AccountRoles -split ' ') {
        $SSORoleCredential = Get-SSORoleCredential -AccessToken $AccessToken -AccountId $AccountId -RoleName $role -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
    
        $Credentials += [pscustomobject][ordered]@{
            AccountId = $AccountId;
            RoleName = $role;
            AccessKey = $SSORoleCredential.AccessKeyId;
            Expiration = $SSORoleCredential.Expiration;
            SecretKey = $SSORoleCredential.SecretAccessKey;
            SessionToken = $SSORoleCredential.SessionToken
        }
    }


    if ($PassThru) {
        $return = @()
        foreach ($item in $Credentials) {
            $return += @{
                AccessKey = $item.AccessKey
                SecretKey = $item.SecretKey
                SessionToken = $item.SessionToken
            }
        }
        return $return
        # return $Credentials | Select-Object AccessKey,SecretKey,SessionToken
    }

    return $Credentials
}

Export-ModuleMember -Function 'Get-AWSSSORoleCredential'