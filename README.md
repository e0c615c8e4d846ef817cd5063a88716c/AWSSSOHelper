# AWSSSOHelper

This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.  Access tokens are cached locally to prevent the need to be pushed to a web browser each time you invoke the script (this is similar behaviour to aws cli v2).

Main usability improvement compared to aws cli is the abillity to specify the -AllRoleCredentials switch and retrieve all credentials for all accounts that you have access to.  You will be prompted to select a role where you have access to multiple roles for an account, alternatively you can specify a role by using the -RoleName parameter.

A basic set of functionality is included, potential future enhancements could be:

- Additional logic to identify expired Session Tokens and automatically renew (safest for now is to renew ahead of any command execution)
- Improved support for systems without GUI
- Usage of aws cli credential cache
- Support for PowerShell 5.1
- Error handling
- ...

## Pre-requisites

- PowerShell Core
- Default AWS Region configured (Set-DefaultAWSRegion)

## Installation

    Install-Module AWSSSOHelper -Force

## Usage

    .EXAMPLE
        Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start"
    .EXAMPLE
        Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles
    .EXAMPLE
        $RoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start"
        Get-S3Bucket -AccessKey $RoleCredentials.AccessKey -SecretKey $RoleCredentials.SecretKey -SessionToken $RoleCredentials.SessionToken
    .EXAMPLE
        $AllRoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AllAccountRoles
        $AllRoleCredentials | Foreach-Object { Get-S3Bucket -AccessKey $_.AccessKey -SecretKey $_.SecretKey -SessionToken $_.SessionToken }
