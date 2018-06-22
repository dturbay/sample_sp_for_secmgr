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
package sample;

import java.lang.reflect.Field;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.httpclient.protocol.ReflectionSocketFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SimpleServiceProviderApplication {


	public static void main(String[] args) {

    // ONLY FOR DEMO!!!!
		trustAllCertificates();

		SpringApplication.run(SimpleServiceProviderApplication.class, args);
	}

  private static void trustAllCertificates() {

    System.setProperty("jsse.enableSNIExtension", "false");
    Security.setProperty("ssl.SocketFactory.provider", "sample.CustomSslSocketFactory");

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

    // Install the all-trusting trust manager
    try {
      SSLContext sc = SSLContext.getInstance("SSL");
      sc.init(null, trustAllCerts, null);
      HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

      HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
        public boolean verify(String urlHostName, SSLSession session) {
          return true;
        }
      });

      // Hack for httpclient lib that does not use DefaultSocketFactory but creates one with
      // the reflection mechanism
      Field field = ReflectionSocketFactory.class.getDeclaredField("REFLECTION_FAILED");
      field.setAccessible(true);
      field.set(null, true);
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }


}
