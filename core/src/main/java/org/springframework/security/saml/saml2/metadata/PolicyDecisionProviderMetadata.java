package org.springframework.security.saml.saml2.metadata;

public class PolicyDecisionProviderMetadata extends Metadata<PolicyDecisionProviderMetadata> {

  public PolicyDecisionProvider getPolicyDecisionProvider() {
    return findProviderByType(PolicyDecisionProvider.class);
  }

  public static PolicyDecisionProviderMetadata copyFrom(Metadata metadata) {
    PolicyDecisionProviderMetadata result = new PolicyDecisionProviderMetadata();
    Metadata.copyProps(metadata, result);
    return result;
  }
}
