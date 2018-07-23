package org.springframework.security.saml.saml2.authentication;

import java.util.Arrays;
import java.util.List;
import org.springframework.security.saml.saml2.ImplementationHolder;

public class AuthzDecisionStatement extends ImplementationHolder {

  public enum DecisionType {PERMIT, DENY, INDETERMINATE}

  public enum Action {
    /** Read action. */
    READ("Read"),
    /** Write action. */
    WRITE("Write"),
    /** Execute action. */
    EXECUTE_ACTION("Execute"),
    /** Delete action. */
    DELETE_ACTION("Delete"),
    /** Control action. */
    CONTROL_ACTION("Control"),
    /** Negated Read action. */
    NEG_READ_ACTION("~Read"),
    /** Negated Write action. */
    NEG_WRITE_ACTION("~Write"),
    /** Negated Execute action. */
    NEG_EXECUTE_ACTION("~Execute"),
    /** Negated Delete action. */
    NEG_DELETE_ACTION("~Delete"),
    /** Negated Control action. */
    NEG_CONTROL_ACTION("~Control"),
    /** HTTP GET action. */
    HTTP_GET_ACTION("GET"),
    /** HTTP HEAD action. */
    HTTP_HEAD_ACTION("HEAD"),
    /** HTTP PUT action. */
    HTTP_PUT_ACTION("PUT"),
    /** HTTP POST action. */
    HTTP_POST_ACTION("POST");

    private String code;

    Action(String code) {
      this.code = code;
    }

    public static Action parse(String code) {
      return Arrays.stream(values()).filter(a -> a.code.equalsIgnoreCase(code)).findFirst().get();
    }
  }

  private String resource;
  private DecisionType decision;
  private List<Action> actions;

  public AuthzDecisionStatement(String resource,
      DecisionType decision, List<Action> actions) {
    this.resource = resource;
    this.decision = decision;
    this.actions = actions;
  }

  public String getResource() {
    return resource;
  }

  public DecisionType getDecision() {
    return decision;
  }

  public List<Action> getActions() {
    return actions;
  }

}
