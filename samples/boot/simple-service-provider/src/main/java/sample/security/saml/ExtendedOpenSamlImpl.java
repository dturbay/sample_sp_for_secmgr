package sample.security.saml;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.time.Clock;
import java.util.List;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

public class ExtendedOpenSamlImpl extends OpenSamlImplementation {

  public ExtendedOpenSamlImpl(Clock time) {
    super(time);
  }

  public String toXml(RequestAbstractType nativeSamlObj) {
    return marshallToXml(nativeSamlObj);
  }

  @Override
  public Saml2Object resolve(String xml, List<SimpleKey> verificationKeys,
      List<SimpleKey> localKeys) {
    try {
      return super.resolve(xml, verificationKeys, localKeys);
    } catch (IllegalArgumentException exception) {
      XMLObject xmlObject = parse(xml.getBytes(UTF_8));
      if (xmlObject instanceof org.opensaml.saml.saml2.core.ArtifactResponse) {
        org.opensaml.saml.saml2.core.ArtifactResponse openSamlArtResponse =
            (org.opensaml.saml.saml2.core.ArtifactResponse) xmlObject;
        return resolveResponse((org.opensaml.saml.saml2.core.Response)openSamlArtResponse.getMessage(), null, null);
      }
      throw new RuntimeException(exception);
    }
  }
}
