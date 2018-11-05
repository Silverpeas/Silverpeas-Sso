/*
 * Copyright (C) 2000 - 2018 Silverpeas
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * As a special exception to the terms and conditions of version 3.0 of
 * the GPL, you may redistribute this Program in connection with Free/Libre
 * Open Source Software ("FLOSS") applications as described in Silverpeas's
 * FLOSS exception.  You should have received a copy of the text describing
 * the FLOSS exception, and it is also available here:
 * "https://www.silverpeas.org/legal/floss_exception.html"
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.silverpeas.sso.saml;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

import static org.silverpeas.sso.saml.SamlLogger.logger;


/**
 * @author silveryocha
 */
class OpenSamlUtils {
  private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

  private OpenSamlUtils() {
    throw new IllegalAccessError("Utility class");
  }

  @SuppressWarnings({"unchecked", "ConstantConditions"})
  static <T> T buildSamlObject(final Class<T> clazz) {
    try {
      XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
      QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
      return (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      throw new IllegalArgumentException("Could not create SAML object");
    }
  }

  static String generateSecureRandomId() {
    return secureRandomIdGenerator.generateIdentifier();
  }

  @SuppressWarnings("ConstantConditions")
  static void logSamlObject(final XMLObject object) {
    Element element = null;

    if (object instanceof SignableSAMLObject &&
        ((SignableSAMLObject) object).isSigned() &&
        object.getDOM() != null) {
      element = object.getDOM();
    } else {
      try {
        Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
        out.marshall(object);
        element = object.getDOM();
      } catch (MarshallingException e) {
        logger().error(e);
      }
    }

    try {
      final Transformer transformer = TransformerFactory.newInstance().newTransformer();
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
      final StreamResult result = new StreamResult(new StringWriter());
      final DOMSource source = new DOMSource(element);
      transformer.transform(source, result);
      final String xmlString = result.getWriter().toString();
      logger().debug(xmlString);
    } catch (TransformerException e) {
      logger().error(e);
    }
  }

  static {
    secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
  }
}
