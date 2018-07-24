package org.springframework.security.saml.saml2.authentication;

public class Artifact {

  private String artifact;

  public Artifact(String artifact) {
    this.artifact = artifact;
  }

  public String getArtifact() {
    return artifact;
  }
}
