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
.PARAMETER RefreshAccessToken
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
    If specified then this function will store the credentials as an AWS profile.
.PARAMETER UseCliCredentialFile
    If specified then this function will store the credentials in the CLI ini-format credential file at the location
    specified by the ProfileLocation parameter. Otherwise the function will store the credentials in the encrypted 
    credential file used by the AWS SDK for .NET and AWS Toolkit for Visual Studio.
.PARAMETER ProfileLocation
    Used to specify the name and location of the ini-format credential file (shared with the AWS CLI and other
    AWS SDKs).
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
    [CmdletBinding(DefaultParameterSetName = 'OutputPSObject')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StartUrl,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [Parameter(ParameterSetName = 'OutputAwsCredential')]
        [Parameter(ParameterSetName = 'UseStoredAwsCredentials')]
        [Parameter(ParameterSetName = 'UseProfile')]
        [string]$AccountId,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [Parameter(ParameterSetName = 'OutputAwsCredential')]
        [Parameter(ParameterSetName = 'UseStoredAwsCredentials')]
        [Parameter(ParameterSetName = 'UseProfile')]
        [string]$RoleName,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [Parameter(ParameterSetName = 'UseProfile')]
        [switch]$AllAccountRoles,

        [Parameter()]
        [switch]$RefreshAccessToken,

        [Parameter()]
        [String]$Region,

        [Parameter(ParameterSetName = 'OutputPSObject')]
        [Switch]$PassThru,

        [Parameter()]
        [String]$ClientName = "default",

        [Parameter()]
        [int]$TimeoutInSeconds = 120,

        [Parameter()]
        [String]$Path = (Join-Path $Home ".awsssohelper"),

        [Parameter(ParameterSetName = 'OutputAwsCredential')]
        [Switch]$OutputAwsCredential,

        [Parameter(ParameterSetName = 'UseStoredAwsCredentials')]
        [Switch]$UseStoredAwsCredentials,

        [Parameter(ParameterSetName = 'UseProfile')]
        [Switch]$UseProfile,

        [Parameter(ParameterSetName = 'UseProfile')]
        [Switch]$UseCliCredentialFile,

        [Parameter(ParameterSetName = 'UseProfile')]
        [String]$ProfileLocation = "$HOME\.aws\credentials"
    )

    # Manually import the AWSPowerShell.NetCore module if present as it is not configured for auto-loading
    if ($PSVersionTable.PSEdition -ne 'Core') {
        $awsPowerShellModuleName = 'AWSPowerShell'
    }
    else {
        $awsPowerShellModuleName = 'AWSPowerShell.NetCore'
    }

    if (Get-Module -Name $awsPowerShellModuleName -ListAvailable) {
        Import-Module -Name $awsPowerShellModuleName
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

    if (Test-Path $CachePath) {
        $AccessToken = Get-Content $CachePath -ErrorAction SilentlyContinue | ConvertFrom-Json
        try {
            Get-SSOAccountList -AccessToken $AccessToken.AccessToken `
                -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false | Out-Null
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

        $Client = Register-SSOOIDCClient -ClientName $ClientName -ClientType $ClientType `
            -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
        $DeviceAuth = Start-SSOOIDCDeviceAuthorization -ClientId $Client.ClientId -ClientSecret $Client.ClientSecret `
            -StartUrl $StartUrl -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())

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
                $newSSOIDCTokenParms = @{
                    ClientId     = $Client.ClientId
                    ClientSecret = $Client.ClientSecret
                    Code         = $DeviceAuth.Code
                    DeviceCode   = $DeviceAuth.DeviceCode
                    GrantType    = "urn:ietf:params:oauth:grant-type:device_code"
                    Credential   = ([Amazon.Runtime.AnonymousAWSCredentials]::new())
                }
                $AccessToken = New-SSOOIDCToken @newSSOIDCTokenParms
            }
            catch {
                Write-Debug ($_.Exception.GetType().FullName, $_.Exception.Message)
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
            $AWSAccounts = Get-SSOAccountList -AccessToken $AccessToken.AccessToken `
                -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false
        }
        catch {
            throw ("Error obtaining account list, access token is invalid.  Try running the command again with " +
                "'-RefreshAccessToken' parameter.")
        }
        if (!$AllAccountRoles) {
            $outGridViewParms = @{ }
            if ($UseStoredAwsCredentials) {
                $outGridViewParms.Title = 'Select AWS Account'
                $outGridViewParms.OutputMode = 'Single'
            }
            else {
                $outGridViewParms.Title = 'Select AWS Account(s)'
                $outGridViewParms.OutputMode = 'Multiple'
            }

            $AccountIds = ($AWSAccounts | Sort-Object AccountName | Out-GridView @outGridViewParms).AccountId
        }
        else {
            $AccountIds = $AWSAccounts | Select-Object -ExpandProperty AccountId
        }
    }
    else {
        $AccountIds = $AccountId
    }
    Write-Verbose "AccountId count: $($AccountIds.Count)"
    foreach ($accountId in $AccountIds) {
        $credentials = GetAccountRoleCredential -AccountId $accountId -AccessToken $AccessToken.AccessToken `
            -RoleName $RoleName -AllAccountRoles:$AllAccountRoles

        if ($UseProfile) {
            try {
                $getIamAccountAliasParms = @{
                    AccessKey    = $credentials[0].AccessKey
                    SecretKey    = $credentials[0].SecretKey
                    SessionToken = $credentials[0].SessionToken
                    Verbose      = $false
                }
                $accountName = Get-IamAccountAlias @getIamAccountAliasParms
            }
            catch {
                $accountName = $accountId
            }
        }

        foreach ($credential in $credentials) {
            if ($OutputAwsCredential) {
                Write-Verbose -Message 'Returning the credentials as an Amazon.Runtime.SessionAWSCredentials object'
                New-AWSCredential -AccessKey $credential.AccessKey -SecretKey $credential.SecretKey `
                    -SessionToken $credential.SessionToken -Verbose:$false
            }
            elseif ($UseProfile) {
                $profileName = "$accountName.$($credential.RoleName)"
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
                Write-Verbose -Message "Storing the credentials in the StoredAwsCredentials Global Variable"
                $setAwsCredentialParms = @{
                    AccessKey    = $credential.AccessKey
                    SecretKey    = $credential.SecretKey
                    SessionToken = $credential.SessionToken
                    Scope        = 'Global'
                    Verbose      = $false
                }
                Set-AWSCredential @setAwsCredentialParms
            }
            else {
                Write-Verbose -Message "Returning the Credentials as a PSCustomObject"
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
        $SSORoleCredential = Get-SSORoleCredential -AccessToken $AccessToken -AccountId $AccountId -RoleName $role `
            -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Verbose:$false
    
        $Credentials += [pscustomobject][ordered]@{
            AccountId    = $AccountId;
            RoleName     = $role;
            AccessKey    = $SSORoleCredential.AccessKeyId;
            Expiration   = $SSORoleCredential.Expiration;
            SecretKey    = $SSORoleCredential.SecretAccessKey;
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
