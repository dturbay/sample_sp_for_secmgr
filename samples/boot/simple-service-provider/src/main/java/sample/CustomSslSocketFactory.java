package sample;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


/**
 * Self-signed friendly SslSocketFactory
 * ONLY for demo
 * NEVER use in prod env
 */
public class CustomSslSocketFactory extends SSLSocketFactory {

  private final SSLSocketFactory delegate;
  private Exception reason;

  final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String authType) {
    }
  }
  };

  public CustomSslSocketFactory() {
    try {
      SSLContext sc = SSLContext.getInstance("SSL");
      sc.init(null, trustAllCerts, null);
      delegate = sc.getSocketFactory();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private Socket throwException() throws SocketException {
    throw (SocketException)(new SocketException(this.reason.toString())).initCause(this.reason);
  }

  public Socket createSocket() throws IOException {
    return delegate.createSocket();
  }

  public Socket createSocket(String var1, int var2) throws IOException {
    return delegate.createSocket(var1, var2);
  }

  public Socket createSocket(Socket var1, String var2, int var3, boolean var4) throws IOException {
    return delegate.createSocket(var1, var2, var3, var4);
  }

  public Socket createSocket(InetAddress var1, int var2) throws IOException {
    return delegate.createSocket(var1, var2);
  }

  public Socket createSocket(String var1, int var2, InetAddress var3, int var4) throws IOException {
    return delegate.createSocket(var1, var2, var3, var4);
  }

  public Socket createSocket(InetAddress var1, int var2, InetAddress var3, int var4) throws IOException {
    return delegate.createSocket(var1, var2, var3, var4);
  }

  public String[] getDefaultCipherSuites() {
    return delegate.getDefaultCipherSuites();
  }

  public String[] getSupportedCipherSuites() {
    return delegate.getSupportedCipherSuites();
  }
}
