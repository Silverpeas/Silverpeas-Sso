A project to centralize the different SSO mechanisms Silverpeas is able to deal with.
Each handled SSO mechanism corresponds to a MAVEN module.

# Azure module

This module uses Microsoft Azure Active Directory Authentication Library (ADAL) for
Java (https://github.com/AzureAD/azure-activedirectory-library-for-java) to perform SSO with the
underlying OAuth2.0 Security protocol.

# Kerberos module

This module uses the Kerberos protocol with the SPNEGO mechanism to perform SSO.

### This module is a kind of fork of the spnego.sourceforge.net project

* Started from [https://github.com/joval/SPNEGO](https://github.com/joval/SPNEGO) which corresponds
  to stable spnego-r7.jar (2010-OCT-15)
* Install Guide, Reference and API Documentation can be found
  at: [http://spnego.sourceforge.net](http://spnego.sourceforge.net)
* Before getting started, the pre-flight doc is a must
  read [http://spnego.sourceforge.net/pre_flight.html](http://spnego.sourceforge.net/pre_flight.html)
* Requires JDK 11 or higher and the Jakarta EE Servlet and SOAP APIs to compile sources

In order to perform user authentication in our Silverpeas product by SSO using the SPNEGO
mechanism within the Kerberos protocol, we were interested in the Sourceforge Spnego project.
Despite several successful integration tests, we identified some additional requirements in
order to manage more precisely, in a JEE application such as Silverpeas, the different possible
errors that can happen during the SSO process for a user.
We then made the necessary developments and have proposed them as a contribution to the
project [https://github.com/joval/SPNEGO] (https://github.com/joval/SPNEGO).
As it has not been integrated, and after several months without any responses nor feedbacks, we
decided to make our own fork of the project that includes our needs.

### The contributions of Silverpeas's version :

* Adding apache maven building capabilities
* Migrating to Jakarta EE
* Adding typed runtime exceptions that can be used to handle SSO errors in the Jakarta EE
  application (not enabled by default, this feature can be enabled by setting the filter
  parameter `spnego.throw.typedRuntimeException` to `true`)
* Updating the SPNEGO HTTP Filter so that it can be used in several URL matchers (filter mapping)
* Modifying the extraction of the remote user name (removing from the Kerberos Principal only the
  part of the Kerberos REALM)
* using Silverpeas's Logger API