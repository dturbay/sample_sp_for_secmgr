package sample;

import com.google.common.base.Stopwatch;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.PolicyDecisionProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.Defaults;
import org.springframework.security.saml.util.Network;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import sample.security.saml.AcceptArtifactSpResponseHandler;
import sample.web.ServiceProviderController;

@Service
public class SecMgrPerformanseTest {

  @Autowired
  private Defaults defaults;
  @Autowired
  private SamlObjectResolver resolver;
  @Autowired
  private Network network;
  @Autowired
  private SamlTransformer transformer;
  @Autowired
  private AcceptArtifactSpResponseHandler acceptArtifactSpResponseHandler;
  @Autowired
  private ServiceProviderController serviceProviderController;

  Logger logger = Logger.getLogger(SecMgrPerformanseTest.class.getName());

  public void startLoad() {
    for (int i = 0 ; i < 10000 ; i++) {
      ExecutorService executor = Executors.newCachedThreadPool();
      executor.submit( () -> loginAndAthz() );
      try {
        Thread.sleep(50); // 200 ms
      } catch (InterruptedException e) {
        throw new RuntimeException(e);
      }
    }
  }

  public void loginAndAthz() {
    ServiceProviderMetadata local = resolver.getLocalServiceProvider("http://localhost:8088/sample-sp");
    String idpId = "http://google.com/enterprise/gsa/T4-KRQHV3XHUQEXY1";
    IdentityProviderMetadata idp = resolver.resolveIdentityProvider(idpId);
    PolicyDecisionProviderMetadata pdpMetadata = resolver.resolvePolicyDecisionProvider(idpId);
    AuthenticationRequest authenticationRequest = defaults.authenticationRequest(local, idp);
    String url = defaults.getAuthnRequestRedirect(idp, authenticationRequest, transformer,
        "http://localhost:8088/sample-sp");

    try {
      BasicCookieStore cookieStore = new BasicCookieStore();
      try (CloseableHttpClient client = HttpClients.custom()
          .setDefaultCookieStore(cookieStore)
          .setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE)
          .setSSLSocketFactory(new SSLConnectionSocketFactory(SSLContexts.custom()
                  .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                  .build()
              )
          ).build()) {
        HttpGet httpGet = new HttpGet(url);
        CloseableHttpResponse response = client.execute(httpGet);

        String postUrl = idp.getIdentityProvider().getSingleSignOnService().get(0).getLocation();
        // System.out.println(cookieStore.toString());
        // System.out.println(EntityUtils.toString(response.getEntity()));
        String gsaSessionId = cookieStore.getCookies().stream()
            .filter(c -> c.getName().equalsIgnoreCase("GSA_SESSION_ID")).findFirst().get()
            .getValue();

        HttpPost httpPost = new HttpPost(postUrl);
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("uDefault", "user1"));
        params.add(new BasicNameValuePair("pwDefault", "password1"));
        httpPost.setEntity(new UrlEncodedFormEntity(params));
        CloseableHttpResponse finishedAthentication = client.execute(httpPost);
        // http://localhost:8088/sample-sp/saml/sp/SSO?SAMLart=AAQAAAWyM7ursAfPEE6uGCq9lBHvTnc%2BVwSJ%2FYyQmnEZeY4IYpzKnNJmkR0%3D&RelayState=http%3A%2F%2Flocalhost%3A8088%2Fsample-sp
        String urlWithArtifactReference = finishedAthentication.getHeaders("Location")[0]
            .getValue();

        MultiValueMap<String, String> parameters =
            UriComponentsBuilder.fromUriString(urlWithArtifactReference).build().getQueryParams();
        Response samLart = acceptArtifactSpResponseHandler
            .resolveArtifact(URLDecoder.decode(parameters.getFirst("SAMLart"), "UTF-8"), local,
                idpId);
        //System.out.println(samLart.getId());

        while (!Thread.currentThread().isInterrupted()) {
          Stopwatch stopwatch = Stopwatch.createStarted();
          Map<String, String> decisionForResources = serviceProviderController
              .getDecisionForResources(local, pdpMetadata, gsaSessionId,
                  Collections.singletonList("http://http-authn:4444/resource1"));
          stopwatch.stop();
          long elapsed = stopwatch.elapsed(TimeUnit.MILLISECONDS);
          logger.info("Authz latency: " + elapsed + "  ms");
          Thread.sleep(1000 * 60);
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
