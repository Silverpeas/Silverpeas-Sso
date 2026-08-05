# Silverpeas SSO

This project centralizes the different Single Sign-On (SSO) mechanisms that
[Silverpeas](https://www.silverpeas.org) is able to deal with in order to authenticate its users
against an external identity provider (IdP).

Each supported SSO mechanism is implemented as a dedicated Maven module. At runtime, each module is
deployed into Silverpeas as a web application (a WAR) that plugs into the Silverpeas authentication
chain: once the user has been authenticated by the external IdP, the module hands back to Silverpeas
a `SilverpeasSsoPrincipal` (the authenticated user's identifier and the identifier of the Silverpeas
domain the user belongs to). Silverpeas then opens the user's session.

## Supported SSO mechanisms

| Module     | Mechanism                                     | Underlying library      |
|------------|-----------------------------------------------|-------------------------|
| `azure`    | OAuth 2.0 / OpenID Connect against Microsoft Entra ID (Azure AD) | MSAL4J |
| `saml`     | SAML 2.0 (e.g. Google Workspace as IdP)       | OpenSAML 5              |
| `kerberos` | Kerberos with the SPNEGO protocol             | forked spnego.sourceforge.net |

## Architecture

All the modules share the same structure and the same runtime pattern.

### Module layout

Each SSO mechanism is a Maven aggregator made of two submodules:

* `<mechanism>-configuration`: the configuration resources (property files, logging definitions)
  packaged so that they can be dropped into the Silverpeas configuration directory.
* `<mechanism>-war`: the web application performing the SSO exchange with the IdP.

### Runtime pattern

Within each WAR, two components collaborate, both mapped under an `/sso/<mechanism>/*` URL space:

* a **servlet `Filter`** that drives the SSO protocol exchange with the external IdP (redirections,
  token/assertion validation, negotiation, ...) and stores the authentication result in the HTTP
  session;
* a **request router** (a servlet extending `SilverpeasSsoHttpServlet`) that reads the
  authentication result and builds the `SilverpeasSsoPrincipal` expected by Silverpeas.

| Module     | Filter                                            | Router                       | URL space              |
|------------|---------------------------------------------------|------------------------------|------------------------|
| `azure`    | `org.silverpeas.sso.azure.AzureFilter`            | `AzureRequestRouter`         | `/sso/azure/*`         |
| `saml`     | `org.silverpeas.sso.saml.SamlFilter`              | `SamlRequestRouter`          | `/sso/saml/*`          |
| `kerberos` | `org.silverpeas.sso.kerberos.spnego.KerberosSpnegoFilter` | `KerberosRequestRouter` | `/sso/kerberos/*` (negotiation on `/sso/kerberos/nego/*`) |

## Modules

### Azure module

Provides SSO with a Microsoft Entra ID (formerly Azure Active Directory) tenant, relying on the
[Microsoft Authentication Library for Java (MSAL4J)](https://github.com/AzureAD/microsoft-authentication-library-for-java)
and the OAuth 2.0 / OpenID Connect security protocol. MSAL4J caches the tokens and, thanks to the
`offline_access` scope, is able to renew the access token silently from a refresh token.

Configuration — `azure.properties`:

| Property                                | Description                                                            |
|-----------------------------------------|------------------------------------------------------------------------|
| `azure.authority.uri`                   | Base URI of the authority server (default `https://login.microsoftonline.com/`). |
| `azure.silverpeas.client.id`            | Application (client) identifier registered in Entra ID.                |
| `azure.silverpeas.client.secret`        | Client secret of the registered application.                           |
| `azure.silverpeas.client.tenant.name`   | Tenant name (or identifier) of the Entra ID directory.                 |
| `azure.silverpeas.domain.id`            | Identifier of the target Silverpeas domain.                            |
| `azure.silverpeas.client.scopes`        | Space-separated OAuth2/OIDC scopes (default `openid profile email offline_access`). |

### SAML module

Provides SSO with the SAML 2.0 protocol, using the
[OpenSAML](https://shibboleth.atlassian.net/wiki/spaces/OSAML/overview) 5 libraries. It has been
designed to work, among others, with Google Workspace acting as the identity provider.

Silverpeas plays the role of the SAML Service Provider (SP): it can sign the requests it sends to the
IdP (with an SP keystore or an explicit certificate/private-key pair) and validates the assertions
returned by the IdP (signature, `NotBefore` / `NotOnOrAfter` conditions, authentication context).

Configuration — `saml.properties` (properties prefixed by `domain.X.` are per Silverpeas domain,
`X` being the domain identifier):

| Property                                              | Description                                             |
|-------------------------------------------------------|---------------------------------------------------------|
| `silverpeas.domain.type`                              | Silverpeas domain type the SAML SSO applies to (e.g. `GOOGLE`). |
| `saml.silverpeas.default.domain.id`                   | Default Silverpeas domain handled by the module.        |
| `domain.X.saml.sso.service.url`                       | IdP Single Sign-On service URL.                         |
| `domain.X.saml.artifact.resolution.service.url`       | IdP artifact resolution service URL.                    |
| `domain.X.saml.sp.keystore.path` / `.pwd` / `.entryId` / `.entryPwd` | SP keystore used to sign requests.       |
| `domain.X.saml.sp.public.certificate.path`            | SP public certificate (alternative to the keystore).    |
| `domain.X.saml.sp.private.key.path` / `.pass`         | SP private key (and optional passphrase).               |
| `domain.X.saml.idp.xml.metadata.path`                 | Path to the IdP XML metadata file.                      |
| `domain.X.saml.idp.public.certificate.path`           | IdP certificate (alternative to the metadata file).     |
| `domain.X.saml.assertion.condition.notBefore.enabled` | Enable the `NotBefore` assertion condition check.       |
| `domain.X.saml.assertion.condition.notOnOrAfter.enabled` | Enable the `NotOnOrAfter` assertion condition check. |
| `domain.X.saml.ac.comparison` / `domain.X.saml.ac.class` | Requested authentication context comparison and class. |

### Kerberos module

Provides SSO with Kerberos through the SPNEGO protocol. This module is a fork of the
[spnego.sourceforge.net](http://spnego.sourceforge.net) project.

The SPNEGO negotiation is handled by `KerberosSpnegoFilter`, configured through `init-param` entries
in the module's `web.xml` (`spnego.krb5.conf`, `spnego.login.conf`, `spnego.login.client.module`,
`spnego.login.server.module`, `spnego.allow.basic`, `spnego.allow.localhost`,
`spnego.throw.typedRuntimeException`, ...). The `krb5.conf` and `login.conf` files must be provided
in the Silverpeas configuration.

Configuration — `kerberos.properties`:

| Property                        | Description                                 |
|---------------------------------|---------------------------------------------|
| `kerberos.silverpeas.domain.id` | Identifier of the target Silverpeas domain. |

#### About the SPNEGO fork

* Started from [https://github.com/joval/SPNEGO](https://github.com/joval/SPNEGO), which corresponds
  to the stable `spnego-r7.jar` (2010-OCT-15).
* Install Guide, Reference and API documentation: [http://spnego.sourceforge.net](http://spnego.sourceforge.net).
* The pre-flight documentation is a must read before getting started:
  [http://spnego.sourceforge.net/pre_flight.html](http://spnego.sourceforge.net/pre_flight.html).

In order to perform user authentication in Silverpeas by an SSO mechanism using SPNEGO and Kerberos,
we were interested in the Sourceforge Spnego project. Despite several successful integration tests,
we identified some additional needs in order to manage more precisely, in a Jakarta EE application
such as Silverpeas, the different possible errors that can happen during the SSO process for a user.
We then made the necessary developments and proposed them as a contribution to the project. As it
has not been integrated, and after several months without any response, we decided to make our own
fork of the project that includes our needs.

The contributions of the Silverpeas version:

* adding Apache Maven building capabilities;
* adding typed runtime exceptions that can be used to handle SSO errors in the Jakarta EE application
  (not activated by default; to activate it, set the filter parameter
  `spnego.throw.typedRuntimeException` to `true`);
* upgrading the SPNEGO HTTP filter so that it can be used with several URL mappings (filter mapping);
* modifying the extraction of the remote user name (removing from the Kerberos Principal only the
  part of the Kerberos REALM);
* using the Silverpeas Logger API.

## Requirements

* Java 17
* Jakarta EE 10
* Apache Maven 3.9+

The build also depends on the Silverpeas artifacts, resolved from the Silverpeas Nexus repository
(see the `<repositories>` section of the root `pom.xml`).

## Building

The recommended way to build the project is to use the provided **dev container**
(`.devcontainer/`), which ships a ready-to-use toolchain: OpenJDK 17, Maven 3.9.16, Groovy 4.0.28
and Node.js 22. This guarantees a build environment consistent with the project requirements.

### With an IDE / the Dev Containers CLI

The dev container is described by `.devcontainer/devcontainer.json`. It is supported natively by
IDEs that understand the Dev Containers specification (VS Code with the *Dev Containers* extension,
JetBrains IntelliJ IDEA, ...):

* open the project folder and let the IDE *"Reopen in Container"* / start the remote dev container;
* the workspace is bind-mounted into the container, along with your local `~/.m2` (Maven cache),
  `~/.ssh` and `~/.gitconfig`, so your Maven settings, SSH keys and Git identity are reused as-is.

You can also drive it from the command line with the
[Dev Containers CLI](https://github.com/devcontainers/cli):

```bash
# build and start the dev container for this project
devcontainer up --workspace-folder .

# run the Maven build inside the container
devcontainer exec --workspace-folder . mvn clean install
```

### Maven goals

Once inside the container, the project is built with Maven from its root:

```bash
mvn clean install
```

Each `<mechanism>-war` module produces a WAR to be deployed into Silverpeas, and each
`<mechanism>-configuration` module packages the property files to be added to the Silverpeas
configuration.

## Configuration

The property files documented above (`azure.properties`, `saml.properties`, `kerberos.properties`,
and the associated logging definitions) are provided by the `*-configuration` modules and are meant
to be deployed into the Silverpeas configuration directory. Fill them in according to your identity
provider and your Silverpeas domains before enabling the corresponding SSO mechanism.

## License

This project is released under the **GNU Affero General Public License v3.0** (AGPL-3.0), with the
Silverpeas [FLOSS exception](https://www.silverpeas.org/legal/floss_exception.html). See the header
of the source files for the full notice.
