A project to centralize the different SSO mechanisms Silverpeas is able to deal with.
Each handled SSO mechanism corresponds to a MAVEN module.

# Azure module

This module uses Microsoft Azure Active Directory Authentication Library (ADAL) for Java (https://github.com/AzureAD/azure-activedirectory-library-for-java) to perform SSO with underlying OAuth2.0 Security protocol.

# Kerberos module

This module uses Keberos with SPNEGO protocol to perform SSO.

### This module is a kind of fork of the spnego.sourceforge.net project
* Started from [https://github.com/joval/SPNEGO](https://github.com/joval/SPNEGO) which corresponds to stable spnego-r7.jar (2010-OCT-15)
* Install Guide, Reference and API Documentation can be found at: [http://spnego.sourceforge.net](http://spnego.sourceforge.net)
* Before getting started, the pre-flight doc is a must read [http://spnego.sourceforge.net/pre_flight.html](http://spnego.sourceforge.net/pre_flight.html)
* Need JDK 1.6 or higher and servlet-api.jar required to compile source

In order to perform user authentication in our Silverpeas product by SSO mechanism using SPNEGO and Kerberos, we were interested in the Sourceforge Spnego project.
Despite several successful integration tests, we identified some additional needs in order to manage more precisely in a JEE application, such as Silverpeas, the different possible errors that can happen during the SSO process for a user.
We then made ​​the necessary developments and have proposed them as a contribution to the project [https://github.com/joval/SPNEGO] (https://github.com/joval/SPNEGO).
As it has not been integrated, and after several months without any response, we decided to make our own fork of the project that includes our needs.

### The contributions of Silverpeas's version :
* adding apache maven building capabilities
* adding typed runtime exception that can be used to handle SSO errors in the JEE application (not activated by default, to activate it set the added filter parameter "spnego.throw.typedRuntimeException" to true)
* upgrading the SPNEGO HTTP Filter so that it can be used in several URL matching (filter mapping)
* modifying the extraction of remote user name (removing from the Kerberos Principal only the part of the Kerberos REALM)
* using Silverpeas's Logger API