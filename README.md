
# Sqyrrl - an HTTP server for files hosted in iRODS

<img src="sqyrrl.jpg" alt="Sqyrrl" width="200"/>

Sqyrrl is an HTTP server which contains an embedded iRODS client and is able to
serve data directly from iRODS.

## Installation

Sqyrrl is a available as and `amd64` binary for Linux, macOS and Windows,
or as a Docker image. Copy the file to the desired location and run it.

## Running Sqyrrl

Sqyrrl authenticates to iRODS using the standard method for an iRODS client i.e.
using the iRODS environment file.

Since Sqyrrl may serve any data that it can access, it's important to use an iRODS user
with appropriate authorisation. In addition to the limitations imposed by the iRODS account
used directly by the server, the server itself may be configured use OpenID Connect for
HTTP client authentication. In this case, the user must also be authenticated by the OIDC
provider and Sqyrrl will only serve data that the user has access to. OIDC user identity is
mapped to an iRODS user account by user name.

If the server is started without OIDC enabled, it will serve only data that is explicitly
set to be readable by the `public` iRODS user.

To start the server, use the following command:

```sh
Configure and start the server.

Usage:
  sqyrrl start [flags]

Flags:
      --cert-file string          Path to the SSL certificate file
      --config string             Path to a TOML configuration file
      --enable-oidc               Enable OpenID Connect authentication
  -h, --help                      help for start
      --host string               Address on which to listen, host part (default "localhost")
      --index-interval duration   Interval at which update the index (default 1m0s)
      --irods-env string          Path to the iRODS environment file
      --key-file string           Path to the SSL private key file
      --port string               Port on which to listen (default "3333")

Global Flags:
      --log-level string   Set the log level (trace, debug, info, warn, error) (default "info")
```

For additional options, use the `--help` flag.

To stop the server, send `SIGINT` or `SIGTERM` to the process. The server will wait for
active connections to close before shutting down.


### Configuration

The preferred way to configure Sqyrrl is to use a TOML configuration file. This file may be
specified using the `--config` flag. This file may be used to provide all the necessary
configuration options and is the only way to pass secrets (OIDC client secret and iRODS
password) to the server.

An example configuration file is provided in the repository. The following fields are recognised:

```toml
Host = "<hostname>"
Port  = "<port>"
IRODSEnvFilePath = "<path to iRODS environment file>"
IRODSPassword = "<iRODS password>"
CertFilePath = "<path to SSL certificate file>"
KeyFilePath = "<path to SSL private key file>"
EnableOIDC  = true # Boolean value
OIDCClientID = "<OICD client ID>"
OIDCClientSecret = "<OIDC client secret>"
OIDCIssuerURL = "<OIDC issuer URL>"
OIDCRedirectURL = "<OIDC redirect URL>"
IndexInterval = "<Interval string>" # e.g. "1m0s", "30s"
```

If `EnableOIDC` is set to false, the OIDC fields are not required and will be ignored, if present.

Command line options and environment variables may also be used to configure the server
for all settings except secrets. The configuration file has highest precedence, followed
by command line options, and finally environment variables.

Sqyrrl respects the `IRODS_ENVIRONMENT_FILE` environment variable, and if that is not set, it will
look for the file in the standard location `$HOME/.irods/irods_environment.json`. Alternatively,
command line option `--irods-env` may be used to set the environment file location explicitly.

If an iRODS authentication file (default `~/.irods/.irodsA`) is present, Sqyrrl will use it
and the iRODS password field is not required and will be ignored, if present.

For backwards compatibility, it's possible to set some OIDC configuration options using
environment variables. The following environment variables are recognised:

- `OIDC_CLIENT_ID` - the client ID for the OIDC provider
- `OIDC_ISSUER_URL` - the URL of the OIDC provider
- `OIDC_REDIRECT_URL` - the URL to which the OIDC provider should redirect after authentication

## Authentication

Sqyrrl supports OpenID Connect for authentication. To enable OpenID Connect, use the
`EnableOIDC` field in the configuration file (or the `--enable-oidc` command line flag).

Sqyrrl will then redirect users to the OIDC provider for authentication. The user will be
redirected back to Sqyrrl after authentication.

## iRODS authentication

Sqyrrl uses the standard iRODS environment file to authenticate to iRODS. If the user has been
authenticated with `iinit` before starting Sqyrrl, the server will use the existing iRODS auth
file created by `iinit`. If the user has not been authenticated, Sqyrrl will require the iRODS
password to be supplied using the `IRODSPassword` field of the Sqyrrl configuration file. Sqyrrl
will then create  the iRODS auth file itself, without requiring `iinit` to be used.

## Running in a container

When running Sqyrrl in a Docker container, configuration files (Sqyrrl configuration file, iRODS
environment file, any existing auth file, SSL certificates) should be mounted into the container.

The docker-compose.yml file in the repository contains an example configuration for running
Sqyrrl in a container.

## Tagging iRODS data objects for display on the home page

This is an experimental feature. It allows the user to tag iRODS data objects with metadata so
that they will be displayed in the Sqyrrl home page for convenience. To tag an iRODS data object,
add a metadata attribute `sqyrrl:index` with value `1`. Data objects may be  grouped together
on the page, under a title, known as a "category". To specify a category for a data object,
add a metadata attribute `sqyrrl:category` with the  value being the category name.

The home page will be re-indexed at the interval specified by the `IndexInterval` field in the
configuration file (or the `--index-interval` command line flag). The home page auto-refreshes
every 30 seconds.

N.B. As go-irodsclient does not support metadata queries across federated zones, this feature
is limited to data objects in the same zone as the iRODS user.

## Dependencies

Sqyrrl uses [go-irodsclient](https://github.com/cyverse/go-irodsclient) to connect to iRODS. 
