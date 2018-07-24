package org.springframework.security.saml.saml2.authentication;

public class ArtifactResolveRequest extends Request<ArtifactResolveRequest> {

  private Artifact artifact;

  public Artifact getArtifact() {
    return artifact;
  }

  public ArtifactResolveRequest setArtifact(Artifact artifact) {
    this.artifact = artifact;
    return this;
  }
}
