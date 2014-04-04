package bug430772;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

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
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Password;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.squareup.okhttp.OkHttpClient;

public class Expect100ContinueTest {

  private Server server;
  private SelectChannelConnector connector;

  @Test
  public void testURLConnection() throws Exception {
    URL url = new URL("http://127.0.0.1:" + connector.getLocalPort());
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setDoOutput(true);
    connection.setRequestMethod("PUT");
    connection.setFixedLengthStreamingMode(100);
    connection.setRequestProperty("Expect", "100-continue");
    connection.connect();
    Assert.assertEquals(401, connection.getResponseCode());
  }

  @Test
  public void testOkHttp() throws Exception {
    OkHttpClient client = new OkHttpClient();
    URL url = new URL("http://127.0.0.1:" + connector.getLocalPort());
    HttpURLConnection connection = client.open(url);
    connection.setDoOutput(true);
    connection.setRequestMethod("PUT");
    connection.setFixedLengthStreamingMode(100);
    connection.setRequestProperty("Expect", "100-continue");
    connection.connect();
    Assert.assertEquals(401, connection.getResponseCode());
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
        req.getSession();
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
    security.setSessionRenewedOnAuthentication(true);
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

    // sessions
    SessionHandler session = new SessionHandler();
    context.setSessionHandler(session);

    server.start();
  }

  @After
  public void stopServer() throws Exception {
    server.stop();
    server = null;
    connector = null;
  }

}
