# Change log for AWSSSOHelper

## [0.0.26] (shout out to @SiloReed)

### Changed

- Improvements to the token expiration logic

### Fixed

- Bug after cached credential expired
- Removed out-null from Get-SSOAccountList

## [0.0.25]

### Changed

- Updated behaviour for -OutputEnvVariables to enable piping to e.g. 'eval -' for use with cli.

## [0.0.24]

### Changed

- Fixed bug with macOS
  ([issue #7](https://github.com/e0c615c8e4d846ef817cd5063a88716c/AWSSSOHelper/issues/7)).

## [0.0.23]

### Changed

- Added support for additional credential output options
  ([issue #5](https://github.com/e0c615c8e4d846ef817cd5063a88716c/AWSSSOHelper/issues/5)).

## [0.0.22]

### Changed

- Added support for AWS.Tools PowerShell Modules
  ([issue #2](https://github.com/e0c615c8e4d846ef817cd5063a88716c/AWSSSOHelper/issues/2)).
- Added support for Windows Powershell v5.1

## [0.0.21] - 2020-05-11

## [0.0.20] - 2020-05-09

### Fixed

- Fixed error with multiple level access on multiple accounts
  ([issue #1](https://github.com/e0c615c8e4d846ef817cd5063a88716c/AWSSSOHelper/issues/1)).
