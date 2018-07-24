package org.springframework.security.saml.saml2.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.security.saml.saml2.authentication.AuthzDecisionStatement.Action;

public class AuthzDecisionQueryRequest extends Request<AuthzDecisionQueryRequest> {

  private Subject subject;
  private String resource;
  private List<Action> actions = new ArrayList<>();

  public AuthzDecisionQueryRequest setSubject(Subject subject) {
    this.subject = subject;
    return this;
  }

  public Subject getSubject() {
    return subject;
  }

  public AuthzDecisionQueryRequest setResource(String resource) {
    this.resource = resource;
    return this;
  }

  public String getResource() {
    return resource;
  }

  public AuthzDecisionQueryRequest setActions(Action ... actions) {
    this.actions = Arrays.asList(actions);
    return this;
  }

  public AuthzDecisionQueryRequest setActions(List<Action> actions) {
    this.actions = actions;
    return this;
  }

  public List<Action> getActions() {
    return actions;
  }
}
