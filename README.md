# AWSSSOHelper

This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.  Access tokens are cached locally to prevent the need to be pushed to a web browser each time you invoke the script (this is similar behaviour to aws cli v2).

Main usability improvement compared to aws cli is the abillity to specify the -AllRoleCredentials switch and retrieve all credentials for all accounts that you have access to.  You will be prompted to select a role where you have access to multiple roles for an account, alternatively you can specify a role by using the -RoleName parameter.

The output options of the credentials can be selected from the following options:

- Output as an array of PSCustomObjects with the following properties: AccountId, RoleName, AccessKey, Expiration, SecretKey, SessionToken.
- Output as an array of hashtables with the following keys: AccessKey, SecretKey, SessionToken. for splatting input to AWS PowerShell cmdlets.
- Output as an `Amazon.Runtime.SessionAWSCredentials` object for input to the `Credential` parameter of AWS PowerShell cmdlets.
- Written as profiles to the AWS SDK .NET encrypted credential file used by the AWS PowerShell cmdlets with a naming convention of `<AccountName>.<RoleName>`.
- Written as profiles to the AWS CLI ini-format credential file with a naming convention of `<AccountName>.<RoleName>`.
- Written to the AWS CLI environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` for use by the AWS CLI and other compatible tooling (Terraform, Sceptre).

A basic set of functionality is included, potential future enhancements could be:

- Additional logic to identify expired Session Tokens and automatically renew (safest for now is to renew ahead of any command execution) - **Done**
- Improved support for systems without GUI - **Done**
- Usage of aws cli credential cache
- Support for PowerShell 5.1 - **Done**
- Error handling
- ...

## Pre-requisites

- PowerShell 5.1 or Core
- Default AWS Region configured (Set-DefaultAWSRegion)
- Either the `AWSPowerShell`, `AWS PowerShell.NetCore` or the required `AWS.Tools` PowerShell modules installed. See [What are the AWS Tools for PowerShell?](https://docs.aws.amazon.com/powershell/latest/userguide/pstools-welcome.html) for information on the differences in the modules.

#### Install AWS PowerShell.NetCore Module (for PowerShell Core)

```powershell
Install-Module AWSPowerShell.NetCore -Force
```

#### Install AWS PowerShell Module (for PowerShell 5.1)

```powershell
Install-Module AWSPowerShell -Force
```

#### Install AWS Tools Modules

```powershell
Install-Module AWS.Tools.Common, AWS.Tools.SSO, AWS.Tools.SSOOIDC -Force
```

## Installation

```powershell
Install-Module AWSSSOHelper -Force
```

## Usage

```powershell
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start"

    Prompt for account and role as applicable and output the credentials as a PSCustomObject.
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles

    Output all account and role credentials as an array of PSCustomObjects.
.EXAMPLE
    $RoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -PassThru
    Get-S3Bucket @RoleCredentials

    Prompt for account and role as applicable and output as a hashtable for splatting on an AWS PowerShell cmdlet.
.EXAMPLE
    $AllRoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles
    $AllRoleCredentials | Foreach-Object { Get-S3Bucket -AccessKey $_.AccessKey -SecretKey $_.SecretKey -SessionToken $_.SessionToken }

    Output all account and role credentials as an array of PSCustomObjects and pipe the properties through
    ForEach-Object to an AWS PowerShell cmdlet.
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -OutputEnvVariables
    aws s3 ls

    Prompt for account and role as applicable and write to the AWS environment variables for use by the AWS ClI and
    other compatible tooling (Terraform, Sceptre etc).
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles -UseProfile
    Get-S3Bucket -Profile aws-account-01.SSORole1

    Output all account and role credentials to profiles within the AWS .NET SDK encrypted credential file with a
    naming convention of <AccountName>.<RoleName>.
.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles -UseProfile -UseCliCredentialFile
    aws s3 ls --profile aws-account-01.SSORole1

    Output all account and role credentials to profiles within the AWS CLI credential file with a naming convention of
    <AccountName>.<RoleName> for use by the AWS CLI.

.EXAMPLE
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AccountId 123456789012 -RoleName SSORole1 -UseStoredAwsCredentials
    Get-S3Bucket

    Get credentials for the specified account ID and role name and write them to the AWS $StoredAwsCredentials variable
    for use by AWS PowerShell cmdlets.
.EXAMPLE
    $awsCredential = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AccountId 123456789012 -RoleName SSORole1 -OutputAwsCredential
    Get-S3Bucket -Credential $awsCredential

    Get credentials for the specified account ID and role name and output them as an Amazon.Runtime.SessionAWSCredentials
    object for use by AWS PowerShell cmdlets.
```
