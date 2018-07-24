package org.springframework.security.saml.saml2;

import java.io.ByteArrayInputStream;
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
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

public class SamlWsClient {

  private OpenSamlImplementation implementation;

  public SamlWsClient(
      OpenSamlImplementation implementation) {
    this.implementation = implementation;
  }

  private SOAPFactory soap11Factory = OMAbstractFactory.getSOAP11Factory();
  private XMLInputFactory xmlFactory = XMLInputFactory.newInstance();

  public Response sendRequest(String request, String endpointUrl) {
    OMNamespace ns = soap11Factory.createOMNamespace(
        "http://www.oasis-open.org/committees/security", "ns1");
    SOAPEnvelope envelope = soap11Factory.createSOAPEnvelope(ns);
    SOAPBody soapBody = soap11Factory.createSOAPBody(envelope);

    try {
      OMElement req = toOMElement(request);
      soapBody.addChild(req);

      Options clientOptions = new Options();
      EndpointReference endpointReference = new EndpointReference(endpointUrl);
      clientOptions.setTo(endpointReference);
      clientOptions.setProperty(HTTPConstants.CHUNKED, false);

      ServiceClient client = new ServiceClient();
      client.setOptions(clientOptions);
      OMElement responseXmlObj = client.sendReceive(req);

      Response response = (Response) implementation
          .resolve(responseXmlObj.toString(), null, null);
      return response;
    } catch (AxisFault | XMLStreamException exception) {
      throw new RuntimeException(exception);
    }
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
