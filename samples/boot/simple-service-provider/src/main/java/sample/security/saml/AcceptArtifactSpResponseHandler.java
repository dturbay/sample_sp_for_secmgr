
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

import java.io.IOException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.SamlWsClient;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.authentication.ArtifactResolveRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;

public class AcceptArtifactSpResponseHandler extends SamlMessageHandler<AcceptArtifactSpResponseHandler> {

	private SamlValidator validator;
  private SamlWsClient samlWsClient;

  @Override
	protected ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) {

		ServiceProviderMetadata local = getResolver().getLocalServiceProvider(getNetwork().getBasePath(request));
    String artifact = request.getParameter("SAMLart");
    try {
      String idpId = (String) request.getSession().getAttribute("idp");
      Response artifactResponse = resolveArtifact(artifact, local, idpId);
      Attribute sessionIdAttr = artifactResponse.getAssertions().get(0).getAttributes()
          .stream().filter(attr -> attr.getName().equalsIgnoreCase("SessionId")).findFirst().get();
      String sessionId = (String) sessionIdAttr.getValues().get(0);
      Cookie sessionCookie = new Cookie("GSA_SESSION_ID", sessionId);
      sessionCookie.setHttpOnly(true);
      sessionCookie.setPath("/");
      response.addCookie(sessionCookie);
      authenticate(artifactResponse, local.getEntityId(), idpId);
      return postAuthentication(request, response);

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
	}

  private Response resolveArtifact(final String artifactString,
      ServiceProviderMetadata local, String idpId)
      throws IllegalArgumentException, SecurityException {

    ArtifactResolveRequest artifactResolve = getDefaults().artifactResolveRequest(artifactString, local);
    String artifactResolveXml = getTransformer().toXml(artifactResolve);

    IdentityProviderMetadata idpMetadata = getResolver().resolveIdentityProvider(idpId);
    Response artifactResponse = samlWsClient.sendRequest(artifactResolveXml, idpMetadata.getIdentityProvider().getArtifactResolutionService().get(0).getLocation());
    return artifactResponse;
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

  public AcceptArtifactSpResponseHandler setSamlWsClient(SamlWsClient wsClient) {
    this.samlWsClient = wsClient;
    return this;
  }
}
