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

package org.springframework.security.saml.spi;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

public class DefaultAuthnRequestHandler extends SamlMessageHandler<DefaultAuthnRequestHandler> {


	@Override
	protected ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException {
		String appBaseWebPath = getNetwork().getBasePath(request);
		ServiceProviderMetadata local = getResolver().getLocalServiceProvider(appBaseWebPath);
		String idpId = request.getParameter("idp");
		request.getSession().setAttribute("idp", idpId);
		IdentityProviderMetadata idp = getResolver().resolveIdentityProvider(idpId);
		AuthenticationRequest authenticationRequest = getDefaults().authenticationRequest(local, idp);
		String url = getDefaults().getAuthnRequestRedirect(idp, authenticationRequest,
				getTransformer(), appBaseWebPath);
		response.sendRedirect(url);
		return ProcessingStatus.STOP;
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		LocalServiceProviderConfiguration sp = getConfiguration().getServiceProvider();
		String prefix = sp.getPrefix();
		String path = prefix + "/discovery";
		return isUrlMatch(request, path) && request.getParameter("idp") != null;
	}


}
