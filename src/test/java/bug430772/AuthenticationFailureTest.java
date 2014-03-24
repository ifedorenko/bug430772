package bug430772;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Password;
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
      private final Set<String> handled = new HashSet<String>();

      @Override
      public Credential authenticateProxy(Proxy proxy, URL url, List<Challenge> challenges)
          throws IOException {
        return authenticate(url);
      }

      Credential authenticate(URL url) {
        if (handled.add(url.getHost() + ":" + url.getPort())) {
          return Credential.basic("user", "password");
        }
        return null;
      }

      @Override
      public Credential authenticate(Proxy proxy, URL url, List<Challenge> challenges)
          throws IOException {
        return authenticate(url);
      }
    };

    OkHttpClient client = new OkHttpClient();
    client.setAuthenticator(auth);
    URL url = new URL("http://127.0.0.1:" + connector.getLocalPort());
    HttpURLConnection connection = client.open(url);
    connection.connect();
    Assert.assertEquals(204, connection.getResponseCode());

    connection = client.open(url);
    connection.connect();
    Assert.assertEquals(204, connection.getResponseCode());
  }

  @Before
  public void startServer() throws Exception {
    server = new Server();

    // connector
    connector = new SelectChannelConnector();
    server.setConnectors(new Connector[] {connector});

    // servlet
    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    context.setContextPath("/");
    server.setHandler(context);
    HttpServlet servlet = new HttpServlet() {
      @Override
      protected void doGet(HttpServletRequest req, HttpServletResponse resp)
          throws ServletException, IOException {
        resp.setStatus(204); // no contents
      }
    };
    context.addServlet(new ServletHolder(servlet), "/*");

    // servlet security
    ConstraintSecurityHandler security = new ConstraintSecurityHandler();
    context.setSecurityHandler(security);
    security.setRealmName("Test realm");
    security.setAuthMethod(Constraint.__BASIC_AUTH);
    security.setStrict(true);
    ConstraintMapping mapping = new ConstraintMapping();
    mapping.setPathSpec("/*");
    Constraint constraint = new Constraint();
    constraint.setRoles(new String[] {"role"});
    constraint.setAuthenticate(true);
    mapping.setConstraint(constraint);
    security.addConstraintMapping(mapping);
    HashLoginService login = new HashLoginService();
    login.putUser("user", new Password("password"), new String[] {"role"});
    security.setLoginService(login);

    server.start();
  }

  @After
  public void stopServer() throws Exception {
    server.stop();
    server = null;
    connector = null;
  }

}
