package bug430772;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.URL;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.squareup.okhttp.OkAuthenticator;
import com.squareup.okhttp.OkHttpClient;

public class AuthenticationFailureTest {

  private Server server;
  private SelectChannelConnector connector;

  @Test
  public void testOkAuthenticator() throws Exception {
    // from http://www.ietf.org/rfc/rfc2617.txt
    // 1.2 Access Authentication Framework
    /*
     * If the origin server does not wish to accept the credentials sent with a request, it SHOULD
     * return a 401 (Unauthorized) response. The response MUST include a WWW-Authenticate header
     * field containing at least one (possibly new) challenge applicable to the requested resource.
     * If a proxy does not accept the credentials sent with a request, it SHOULD return a 407 (Proxy
     * Authentication Required). The response MUST include a Proxy-Authenticate header field
     * containing a (possibly new) challenge applicable to the proxy for the requested resource.
     */

    // the test proxy server does not accept any proxy credentials
    // I expect okhttp client to fail the request with http status 407 if provided proxy credentials
    // are not accepted by the server.
    // as of okhttp 1.5.2, the client goes into endless request loop


    OkAuthenticator auth = new OkAuthenticator() {
      @Override
      public Credential authenticateProxy(Proxy proxy, URL url, List<Challenge> challenges)
          throws IOException {
        return Credential.basic("username", "password");
      }

      @Override
      public Credential authenticate(Proxy proxy, URL url, List<Challenge> challenges)
          throws IOException {
        return Credential.basic("username", "password");
      }
    };
    OkHttpClient client = new OkHttpClient();
    client.setAuthenticator(auth);
    URL url = new URL("http://127.0.0.1:"+connector.getLocalPort());
    HttpURLConnection connection = client.open(url);
    connection.connect();
    Assert.assertEquals(401, connection.getResponseCode());
  }

  @Before
  public void startServer() throws Exception {
    server = new Server();
    server.setHandler(new AbstractHandler() {
      @Override
      public void handle(String target, Request baseRequest, HttpServletRequest request,
          HttpServletResponse response) throws IOException, ServletException {

        // Enumeration<String> headers = request.getHeaderNames();
        // while (headers.hasMoreElements()) {
        // String header = headers.nextElement();
        // Enumeration<String> values = request.getHeaders(header);
        // StringBuilder sb = new StringBuilder();
        // sb.append(header).append(":");
        // while (values.hasMoreElements()) {
        // sb.append(' ').append(values.nextElement());
        // }
        // System.err.println(sb.toString());
        // }

        response.setStatus(401);
        // response
        // .addHeader(
        // "Proxy-Authenticate",
        // "Digest realm=\"Digest authentication\", nonce=\"OtEqUwAAAADwQVXL3n8AAEBt6j4AAAAA\", qop=\"auth\", stale=false");
        response.addHeader("WWW-Authenticate", "Basic realm=\"Basic authentication\"");
        baseRequest.setHandled(true);
      }
    });
    connector = new SelectChannelConnector();
    server.setConnectors(new Connector[] {connector});
    server.start();
  }

  @After
  public void stopServer() throws Exception {
    server.stop();
    server = null;
    connector = null;
  }

}
