package org.springframework.security.saml.saml2.metadata;

import java.util.LinkedList;
import java.util.List;

public class PolicyDecisionProvider extends SsoProvider<PolicyDecisionProvider> {

  private List<Endpoint> authzService = new LinkedList<>();

  public List<Endpoint> getAuthzService() {
    return authzService;
  }

  public void setAuthzService(
      List<Endpoint> authzService) {
    this.authzService = authzService;
  }
}
