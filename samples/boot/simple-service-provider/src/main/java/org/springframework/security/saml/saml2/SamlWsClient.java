package org.springframework.security.saml.saml2;

import java.io.ByteArrayInputStream;
import java.util.UUID;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Action;
import org.opensaml.saml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.PolicyDecisionProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

public class SamlAuthzClient {

  @Autowired
  private OpenSamlImplementation implementation;

  private SOAPFactory soap11Factory = OMAbstractFactory.getSOAP11Factory();
  private XMLInputFactory xmlFactory = XMLInputFactory.newInstance();

  public Response sendAuthzRequest(String resource, String sessionId,
      ServiceProviderMetadata local,
      PolicyDecisionProviderMetadata pdpMetadata) {
    AuthzDecisionQuery query = makeAuthzQuery(new DateTime(), sessionId, resource, local);
    String queryXmlRep = implementation.marshallToXml(query);
    OMNamespace ns = soap11Factory.createOMNamespace(
        "http://www.oasis-open.org/committees/security", "ns1");
    SOAPEnvelope envelope = soap11Factory.createSOAPEnvelope(ns);
    SOAPBody soapBody = soap11Factory.createSOAPBody(envelope);

    try {
      OMElement req = toOMElement(queryXmlRep);
      soapBody.addChild(req);

      Options clientOptions = new Options();
      String authzEndpoint = pdpMetadata.getPolicyDecisionProvider().getAuthzService().get(0)
          .getLocation();
      EndpointReference endpointReference = new EndpointReference(authzEndpoint);
      clientOptions.setTo(endpointReference);
      clientOptions.setProperty(HTTPConstants.CHUNKED, false);

      ServiceClient client = new ServiceClient();
      client.setOptions(clientOptions);
      OMElement authzResponseXmlObj = client.sendReceive(req);

      Response authzResponse = (Response) implementation
          .resolve(authzResponseXmlObj.toString(), null, null);
      return authzResponse;
    } catch (AxisFault | XMLStreamException exception) {
      throw new RuntimeException(exception);
    }

  }

  private AuthzDecisionQuery makeAuthzQuery(DateTime issueInstant, String sessionId, String resource,
      ServiceProviderMetadata local) {

    AuthzDecisionQuery query = implementation.buildSAMLObject(AuthzDecisionQuery.class);
    query.setID(UUID.randomUUID().toString());
    query.setVersion(SAMLVersion.VERSION_20);

    Issuer issuer = implementation.buildSAMLObject(Issuer.class);
    issuer.setValue(local.getEntityId());
    query.setIssuer(issuer);

    query.setIssueInstant(issueInstant);

    Subject subject = implementation.buildSAMLObject(Subject.class);
    NameID nameID = implementation.buildSAMLObject(NameID.class);
    nameID.setValue(sessionId);
    subject.setNameID(nameID);
    query.setSubject(subject);

    query.setResource(resource);

    Action action = implementation.buildSAMLObject(Action.class);
    action.setAction(Action.HTTP_GET_ACTION);
    action.setNamespace(Action.GHPP_NS_URI);

    query.getActions().add(action);

    return query;
  }

  /**
   * Converts a JDOM document into an Axiom OMElement.
   */
  private OMElement toOMElement(String doc) throws XMLStreamException {
    byte[] xmlBytes = doc.getBytes();

    //create the parser
    XMLStreamReader parser =
        xmlFactory.createXMLStreamReader(
            new ByteArrayInputStream(xmlBytes));
    OMXMLParserWrapper builder = OMXMLBuilderFactory.createStAXOMBuilder(parser);
    //get the root element of the XML
    OMElement documentElement = builder.getDocumentElement();
    return documentElement;
  }

}
