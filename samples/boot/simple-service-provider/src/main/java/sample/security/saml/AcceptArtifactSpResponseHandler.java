
/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package sample.security.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.axis2.client.ServiceClient;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.transport.http.HTTPConstants;

import javax.xml.stream.XMLStreamReader;

import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;

import org.opensaml.saml.saml2.core.Issuer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;

public class AcceptArtifactSpResponseHandler extends SamlMessageHandler<AcceptArtifactSpResponseHandler> {

	private SamlValidator validator;
  private ExtendedOpenSamlImpl implementation;

  @Override
	protected ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException {

		ServiceProviderMetadata local = getResolver().getLocalServiceProvider(getNetwork().getBasePath(request));
    String artifact = request.getParameter("SAMLart");
    try {
      // IdentityProviderMetadata localIdentityProvider = getResolver()
      //     .getLocalIdentityProvider(getNetwork().getBasePath(request));
      Response artifactResponse = resolveArtifact(artifact, local);
      // TODO: GET THIS ID FROM CONFIGURATION
      authenticate(artifactResponse, local.getEntityId(), "http://google.com/enterprise/gsa/T4-KRQHV3XHUQEXY");
      return postAuthentication(request, response);

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
	}

  // make it once
  SOAPFactory soap11Factory = OMAbstractFactory.getSOAP11Factory();

  private Response resolveArtifact(final String artifactString,
      ServiceProviderMetadata local)
      throws IllegalArgumentException, SecurityException, AxisFault, XMLStreamException {
    // populate SAML request
    ArtifactResolve artifactResolve = implementation.buildSAMLObject(ArtifactResolve.class);
    Artifact artifact = implementation.buildSAMLObject(Artifact.class);
    artifact.setArtifact(artifactString);
    artifactResolve.setArtifact(artifact);
    Issuer issuer = implementation.buildSAMLObject(Issuer.class);
    issuer.setValue(local.getEntityId());
    artifactResolve.setIssuer(issuer);
    String artifactResolveXml = implementation.toXml(artifactResolve);

    OMNamespace ns = soap11Factory.createOMNamespace(
        "http://www.oasis-open.org/committees/security", "ns1");
    SOAPEnvelope envelope = soap11Factory.createSOAPEnvelope(ns);
    SOAPBody soapBody = soap11Factory.createSOAPBody(envelope);

    OMElement req = toOMElement(artifactResolveXml);
    soapBody.addChild(req);

    Options clientOptions = new Options();
    // TODO: GET THIS URL FROM CONFIGURATION, MUST BE HTTPS
    EndpointReference endpointReference = new EndpointReference("http://secmgr:8080/security-manager/samlartifact");
    clientOptions.setTo(endpointReference);
    clientOptions.setProperty(HTTPConstants.CHUNKED, false);

    ServiceClient client = new ServiceClient();
    client.setOptions(clientOptions);
    OMElement artResolveResponse = client.sendReceive(req);
    Response artifactResponse = (Response) implementation.resolve(artResolveResponse.toString(), null, null);

    return artifactResponse;
  }


	XMLInputFactory xmlFactory = XMLInputFactory.newInstance();
  /**
   * Converts a JDOM document into an Axiom OMElement.
   */
  private OMElement toOMElement(String doc) throws XMLStreamException {
    byte[] xmlBytes = doc.getBytes();

    //create the parser
		XMLStreamReader parser =
        xmlFactory.createXMLStreamReader(
            new ByteArrayInputStream(xmlBytes));
    //create the builder
    // StAXOMBuilder builder = new StAXOMBuilder(parser);
		OMXMLParserWrapper builder = OMXMLBuilderFactory.createStAXOMBuilder(parser);
    //get the root element of the XML
    OMElement documentElement = builder.getDocumentElement();
    return documentElement;
  }


	@Override
	public boolean supports(HttpServletRequest request) {
		LocalServiceProviderConfiguration sp = getConfiguration().getServiceProvider();
		String prefix = sp.getPrefix();
		String path = prefix + "/SSO";
		return isUrlMatch(request, path) && request.getParameter("SAMLart") != null;
	}

	public SamlValidator getValidator() {
		return validator;
	}

	protected void authenticate(Response r, String spEntityId, String idpEntityId) {
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			r.getAssertions().get(0),
			idpEntityId,
			spEntityId
		);
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	protected ProcessingStatus postAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws IOException {
		response.sendRedirect(request.getContextPath() + "/");
		return ProcessingStatus.STOP;
	}

	public AcceptArtifactSpResponseHandler setValidator(SamlValidator validator) {
		this.validator = validator;
		return this;
	}

  public SamlMessageHandler setImplementation(ExtendedOpenSamlImpl implementation) {
    this.implementation = implementation;
    return this;
  }
}