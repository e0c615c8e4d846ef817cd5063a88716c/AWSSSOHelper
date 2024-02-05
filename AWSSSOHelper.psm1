<#
.SYNOPSIS
    This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.
.DESCRIPTION
    This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.
    Access tokens are cached locally to prevent the need to be pushed to a web browser each time you invoke the script
    (this is similar behaviour to aws cli v2).

    Main usability enhancement compared to aws cli 2 is the abillity to specify the -AllRoleCredentials switch and retrieve
    all credentials for all accounts that you have access to.  You will be prompted to select a role where you have access
    to multiple roles for an account, alternatively you can specify a role by using the -RoleName parameter.
.PARAMETER StartUrl
    The URL for the AWS SSO user portal. For more information, see Using the User Portal in the AWS Single Sign-On User
    Guide.
.PARAMETER AccountId 
    The ID of the AWS Account to use for filtering roles.
.PARAMETER RoleName
    The name of the role to use for filtering roles.
.PARAMETER AllAccountRoles
    If specified, credentials for all roles and accounts will be obtained.
.PARAMETER ClientName
    The friendly name for the SSO OIDC Client.
.PARAMETER ClientType
    The SSO OIDC Client type. This is currently fixed with a value of 'Public'.
.PARAMETER RefreshAccessToken
    If specified, the SSO access token will be refreshed.
.PARAMETER Region
    The system name of an AWS region where the AWS SSO service resides.
.PARAMETER PassThru
    If specified, only the AccessKey, SecretKey and SessionToken are returned.
.PARAMETER TimeoutInSeconds
    The maximum length of time to wait for a token response from AWS SSO.
.PARAMETER Path
    The directory for storing the AWSSSOHelper access token cache
.PARAMETER OutputAwsCredential
    If specified, an AWSCredential object will be returned which can be used as input for the Credential parameter on
    other AWS PowerShell cmdlets.
.PARAMETER UseStoredAwsCredentials
    If specified, the credentials will be stored in the shell variable $StoredAWSCredentials for use by other AWS
    PowerShell cmdlets.
.PARAMETER UseProfile
    If specified then this function will store the credentials as an AWS profile in the encrypted credential file used
    by the AWS SDK for .NET and AWS Toolkit for Visual Studio.
.PARAMETER UseCliCredentialFile
    If specified then this function will store the credentials in the CLI ini-format credential file at the location
    specified by the ProfileLocation parameter rather than the AWS SDK .NET encrypted credential file.
.PARAMETER ProfileLocation
    Used to specify the name and location of the ini-format credential file (shared with the AWS CLI and other
    AWS SDKs).
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start'

    Prompt for account and role as applicable and output the credentials as a PSCustomObject.
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -AllAccountRoles

    Output all account and role credentials as an array of PSCustomObjects.
.EXAMPLE
    $RoleCredentials = Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -PassThru
    Get-S3Bucket @RoleCredentials

    Prompt for account and role as applicable and output as a hashtable for splatting on an AWS PowerShell cmdlet.
.EXAMPLE
    $AllRoleCredentials = Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -AllAccountRoles
    $AllRoleCredentials | Foreach-Object { Get-S3Bucket -AccessKey $_.AccessKey -SecretKey $_.SecretKey -SessionToken $_.SessionToken }

    Output all account and role credentials as an array of PSCustomObjects and pipe the properties through
    ForEach-Object to an AWS PowerShell cmdlet.
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -OutputEnvVariables
    aws s3 ls

    Prompt for account and role as applicable and write to the AWS environment variables for use by the AWS ClI and
    other compatible tooling (Terraform, Sceptre etc).
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -AllAccountRoles -UseProfile
    Get-S3Bucket -Profile aws-account-01.SSORole1

    Output all account and role credentials to profiles within the AWS .NET SDK encrypted credential file with a
    naming convention of <AccountName>.<RoleName>.
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -AllAccountRoles -UseProfile -UseCliCredentialFile
    aws s3 ls --profile aws-account-01.SSORole1

    Output all account and role credentials to profiles within the AWS CLI credential file with a naming convention of
    <AccountName>.<RoleName> for use by the AWS CLI.

.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -AccountId 123456789012 -RoleName SSORole1 -UseStoredAwsCredentials
    Get-S3Bucket

    Get credentials for the specified account ID and role name and write them to the AWS $StoredAwsCredentials variable
    for use by AWS PowerShell cmdlets.
.EXAMPLE
    $awsCredential = Get-AWSSSORoleCredential -StartUrl 'https://mycompany.awsapps.com/start' -AccountId 123456789012 -RoleName SSORole1 -OutputAwsCredential
    Get-S3Bucket -Credential $awsCredential

    Get credentials for the specified account ID and role name and output them as an Amazon.Runtime.SessionAWSCredentials
    object for use by AWS PowerShell cmdlets.
.INPUTS
    None
.OUTPUTS
    System.Management.Automation.PSObject
    Amazon.Runtime.SessionAWSCredentials
#>

function Get-AWSSSORoleCredential {
    [CmdletBinding(DefaultParameterSetName = 'OutputPSObject')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StartUrl,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [Parameter(ParameterSetName = 'OutputAwsCredential')]
        [Parameter(ParameterSetName = 'UseStoredAwsCredentials')]
        [Parameter(ParameterSetName = 'UseProfile')]
        [Parameter(ParameterSetName = 'OutputEnvVariables')]
        [Parameter(ParameterSetName = 'UseProfileAllAccountRoles')]
        [string]$AccountId,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [Parameter(ParameterSetName = 'OutputAwsCredential')]
        [Parameter(ParameterSetName = 'UseStoredAwsCredentials')]
        [Parameter(ParameterSetName = 'UseProfile')]
        [Parameter(ParameterSetName = 'OutputEnvVariables')]
        [string]$RoleName,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [Parameter(ParameterSetName = 'UseProfileAllAccountRoles')]
        [switch]$AllAccountRoles,

        [Parameter()]
        [switch]$RefreshAccessToken,

        [Parameter()]
        [string]$Region,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [switch]$PassThru,

        [Parameter()]
        [string]$ClientName = 'default',

        [Parameter()]
        [ValidateSet('Public')]
        [string]$ClientType = 'Public',

        [Parameter()]
        [int]$TimeoutInSeconds = 120,

        [Parameter()]
        [string]$Path = (Join-Path $Home '.awsssohelper'),

        [Parameter(ParameterSetName = 'OutputAwsCredential')]
        [switch]$OutputAwsCredential,

        [Parameter(ParameterSetName = 'UseStoredAwsCredentials')]
        [switch]$UseStoredAwsCredentials,

        [Parameter(ParameterSetName = 'UseProfile')]
        [Parameter(ParameterSetName = 'UseProfileAllAccountRoles')]
        [switch]$UseProfile,

        [Parameter(ParameterSetName = 'UseProfile')]
        [Parameter(ParameterSetName = 'UseProfileAllAccountRoles')]
        [switch]$UseCliCredentialFile,

        [Parameter(ParameterSetName = 'UseProfile')]
        [Parameter(ParameterSetName = 'UseProfileAllAccountRoles')]
        [string]$ProfileLocation = (Join-Path (Join-Path $HOME ".aws") "credentials"),

        [Parameter(ParameterSetName = 'OutputEnvVariables')]
        [switch]$OutputEnvVariables
    )

    # Manually import the AWSPowerShell.NetCore module if present as it is not configured for auto-loading
    if ($PSVersionTable.PSEdition -ne 'Core') {
        $awsPowerShellModuleName = 'AWSPowerShell'
    }
    else {
        $awsPowerShellModuleName = 'AWSPowerShell.NetCore'
    }

    if (Get-Module -Name $awsPowerShellModuleName -ListAvailable) {
        Import-Module -Name $awsPowerShellModuleName -Verbose:$false
    }

    if ($Region) {
        Set-DefaultAWSRegion $Region
    }
    elseif (($null -eq (Get-DefaultAWSRegion).Region)) {
        throw ("No default AWS region configured, specify '-Region <region>' parameter or configure defaults using " +
            "'Set-DefaultAWSRegion'.")
    }
    else {
        $Region = (Get-DefaultAWSRegion).Region
    }

    $CachePath = Join-Path $Path $ClientName

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }

    # Intialize $RefreshAccessToken = $true because the default should be to obtain a new access token 
    $RefreshAccessToken = $true
    if (Test-Path $CachePath) {
        $SSOCredentials = Get-Content $CachePath -ErrorAction SilentlyContinue | ConvertFrom-Json
        if ($null -eq $SSOCredentials.AWSToken.AccessToken) {
            Write-Host 'Access token is null. A new access token will be obtained via SSO.'
        } else {
            try {
                $accountList = Get-SSOAccountList -AccessToken $SSOCredentials.AWSToken.AccessToken `
                    -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false | Out-Null
            }
            catch {
                Write-Host 'Cannot retrieve a cached access token. A new access token will be obtained via SSO.'
            }
        }
    }

    if (($null -ne $SSOCredentials.Expiration) -and ($null -ne $accountList)) {
        if ((Get-Date) -lt $SSOCredentials.Expiration) {
            $RefreshAccessToken = $false
        }
    }

    if ($RefreshAccessToken) {
        if ($null -ne $SSOCredentials.AWSToken) {
            # Clear cached data because token needs to be refreshed
            Clear-Variable SSOCredentials
        }

        $Client = Register-SSOOIDCClient -ClientName $ClientName -ClientType $ClientType -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
        $DeviceAuth = Start-SSOOIDCDeviceAuthorization -ClientId $Client.ClientId -ClientSecret $Client.ClientSecret -StartUrl $StartUrl -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
        Write-Host ("Only confirm in the browser if the code displayed in the browser matches this code: {0}" -f $DeviceAuth.UserCode)
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
        
        Write-Host 'Waiting for SSO login via browser...'
        $SSOStart = Get-Date
        
        while (!$SSOCredentials.AWSToken -and ((New-TimeSpan $SSOStart (Get-Date)).TotalSeconds -lt $TimeoutInSeconds)) {
            try {
                $newSSOIDCTokenParms = @{
                    ClientId     = $Client.ClientId
                    ClientSecret = $Client.ClientSecret
                    Code         = $DeviceAuth.Code
                    DeviceCode   = $DeviceAuth.DeviceCode
                    GrantType    = 'urn:ietf:params:oauth:grant-type:device_code'
                    Credential   = ([Amazon.Runtime.AnonymousAWSCredentials]::new())
                }
                $AWSToken = New-SSOOIDCToken @newSSOIDCTokenParms
                # Create a custom object to store the AWS Access Token along with an Expiration timestamp
                $SSOCredentials = New-Object PSCustomObject @{
                    AWSToken = $AWSToken
                    Expiration = (Get-Date).AddSeconds($AWSToken.ExpiresIn)
                }
            }
            catch {
                Write-Debug -Message ($_.Exception.GetType().FullName, $_.Exception.Message | Out-String)
                Start-Sleep -Seconds 5
            }
        }
        if (!$SSOCredentials.AWSToken) {
            throw 'No access token obtained, exiting.'
        }
        
        $SSOCredentials | ConvertTo-Json -Depth 10 | Set-Content $CachePath

    }

    try {
        $awsAccounts = Get-SSOAccountList -AccessToken $SSOCredentials.AWSToken.AccessToken `
            -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false
    }
    catch {
        throw ('Error obtaining account list, access token is invalid.  Try running the command again with ' +
            "'-RefreshAccessToken' parameter.")
    }

    if (!$AccountId) {
        if (!$AllAccountRoles) {
            $outGridViewParms = @{}
            if ($UseStoredAwsCredentials) {
                $outGridViewParms.Title = 'Select AWS Account'
                $outGridViewParms.OutputMode = 'Single'
            }
            else {
                $outGridViewParms.Title = 'Select AWS Account(s)'
                $outGridViewParms.OutputMode = 'Multiple'
            }

            $accounts = $awsAccounts | Sort-Object AccountName | Out-GridView @outGridViewParms
        }
        else {
            $accounts = $awsAccounts
        }
    }
    else {
        $accounts = $awsAccounts | Where-Object -Property AccountId -EQ $AccountId
    }

    foreach ($account in $accounts) {
        $credentials = GetAccountRoleCredential -AccountId $account.AccountId -AccessToken $SSOCredentials.AWSToken.AccessToken `
            -RoleName $RoleName -AllAccountRoles:$AllAccountRoles

        foreach ($credential in $credentials) {
            if ($OutputAwsCredential) {
                Write-Verbose -Message 'Outputting the credentials as an Amazon.Runtime.SessionAWSCredentials object'
                New-AWSCredential -AccessKey $credential.AccessKey -SecretKey $credential.SecretKey `
                    -SessionToken $credential.SessionToken -Verbose:$false
            }
            elseif ($UseProfile) {
                $profileName = "$($account.AccountName).$($credential.RoleName)"
                $setAwsCredentialParms = @{
                    StoreAs      = $profileName
                    AccessKey    = $credential.AccessKey
                    SecretKey    = $credential.SecretKey
                    SessionToken = $credential.SessionToken
                    Verbose      = $false
                }
                if ($UseCliCredentialFile) {
                    Write-Verbose -Message (
                        "Storing the credentials as AWS profile $profileName in the AWS CLI credential file")
                    $setAwsCredentialParms.ProfileLocation = $ProfileLocation
                }
                else {
                    Write-Verbose -Message (
                        "Storing the credentials as AWS profile $profileName in the AWS .NET SDK Credential store")
                }
                Set-AWSCredential @setAwsCredentialParms
            }
            elseif ($UseStoredAwsCredentials) {
                Write-Verbose -Message 'Storing the credentials in the $StoredAwsCredentials Global Variable'
                $setAwsCredentialParms = @{
                    AccessKey    = $credential.AccessKey
                    SecretKey    = $credential.SecretKey
                    SessionToken = $credential.SessionToken
                    Scope        = 'Global'
                    Verbose      = $false
                }
                Set-AWSCredential @setAwsCredentialParms
            }
            elseif ($OutputEnvVariables) {
                Write-Verbose -Message 'Outputting the credentials as the AWS environment variables'
                $env:AWS_ACCESS_KEY_ID = $credential.AccessKey
                $env:AWS_SECRET_ACCESS_KEY = $credential.SecretKey
                $env:AWS_SESSION_TOKEN = $credential.SessionToken
                "export AWS_ACCESS_KEY_ID=$($credential.AccessKey)"
                "export AWS_SECRET_ACCESS_KEY=$($credential.SecretKey)"
                "export AWS_SESSION_TOKEN=$($credential.SessionToken)"
            }
            else {
                Write-Verbose -Message 'Outputting the Credentials as a PSCustomObject'
                $credential
            }
        }
    }
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
        $SSORoles = Get-SSOAccountRoleList -AccessToken $AccessToken -AccountId $AccountId `
            -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false
        if ($SSORoles.Count -eq 1) {
            $AccountRoles = ($SSORoles | Select-Object -First 1).RoleName
        }
        elseif (!$AllAccountRoles) {
            $AccountRoles = ($SSORoles | Out-GridView -PassThru -Title 'Select AWS SSO Role').RoleName
        }
        else {
            $AccountRoles = $SSORoles.RoleName
        }
    }
    else {
        $AccountRoles = $RoleName
    }

    foreach ($role in $AccountRoles -split ' ') {
        $SSORoleCredential = Get-SSORoleCredential -AccessToken $AccessToken -AccountId $AccountId -RoleName $role `
            -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false

        $SSOAccountName = (Get-SSOAccountList -AccessToken $AccessToken `
            -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false |
                Where-Object -Property AccountId -EQ $AccountID).AccountName

        $Credentials += [pscustomobject][ordered]@{
            AccountId    = $AccountId
            AccountName  = $SSOAccountName
            RoleName     = $role
            AccessKey    = $SSORoleCredential.AccessKeyId
            Expiration   = $SSORoleCredential.Expiration
            SecretKey    = $SSORoleCredential.SecretAccessKey
            SessionToken = $SSORoleCredential.SessionToken
        }
    }

    if ($PassThru) {
        $return = @()
        foreach ($item in $Credentials) {
            $return += @{
                AccessKey    = $item.AccessKey
                SecretKey    = $item.SecretKey
                SessionToken = $item.SessionToken
            }
        }
        return $return
    }
    else {
        return $Credentials
    }
}
