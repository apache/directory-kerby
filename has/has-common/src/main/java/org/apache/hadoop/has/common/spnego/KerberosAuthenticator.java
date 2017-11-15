/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
package org.apache.hadoop.has.common.spnego;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.has.common.util.ConnectionConfigurator;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import static org.apache.hadoop.has.common.util.PlatformName.IBM_JAVA;

/**
 * Borrow the class from Apache Hadoop
 */

/**
 * The {@link KerberosAuthenticator} implements the Kerberos SPNEGO authentication sequence.
 * <p>
 * It uses the default principal for the Kerberos cache (normally set via kinit).
 * <p>
 */
public class KerberosAuthenticator implements Authenticator {
  
  private static final Logger LOG = LoggerFactory.getLogger(KerberosAuthenticator.class);

  /**
   * HTTP header used by the SPNEGO server endpoint during an authentication sequence.
   */
  public static final String WWW_AUTHENTICATE = "WWW-Authenticate";

  /**
   * HTTP header used by the SPNEGO client endpoint during an authentication sequence.
   */
  public static final String AUTHORIZATION = "Authorization";

  /**
   * HTTP header prefix used by the SPNEGO client/server endpoints during an authentication sequence.
   */
  public static final String NEGOTIATE = "Negotiate";

  private static final String AUTH_HTTP_METHOD = "OPTIONS";

  private static String keytabPrincipal = null;
  private static String keytabFile = null;

  /*
  * Defines the Kerberos configuration that will be used to obtain the Kerberos principal from the
  * Kerberos cache.
  */
  private static class KerberosConfiguration extends Configuration {

    private static final String OS_LOGIN_MODULE_NAME;
    private static final boolean WINDOWS = System.getProperty("os.name").startsWith("Windows");
    private static final boolean IS_64_BIT = System.getProperty("os.arch").contains("64");
    private static final boolean AIX = System.getProperty("os.name").equals("AIX");

    /* Return the OS login module class name */
    private static String getOSLoginModuleName() {
      if (IBM_JAVA) {
        if (WINDOWS) {
          return IS_64_BIT ? "com.ibm.security.auth.module.Win64LoginModule"
              : "com.ibm.security.auth.module.NTLoginModule";
        } else if (AIX) {
          return IS_64_BIT ? "com.ibm.security.auth.module.AIX64LoginModule"
              : "com.ibm.security.auth.module.AIXLoginModule";
        } else {
          return "com.ibm.security.auth.module.LinuxLoginModule";
        }
      } else {
        return WINDOWS ? "com.sun.security.auth.module.NTLoginModule"
            : "com.sun.security.auth.module.UnixLoginModule";
      }
    }

    static {
      OS_LOGIN_MODULE_NAME = getOSLoginModuleName();
    }

    private static final AppConfigurationEntry OS_SPECIFIC_LOGIN =
      new AppConfigurationEntry(OS_LOGIN_MODULE_NAME,
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                new HashMap<String, String>());

    private static final Map<String, String> KEYTAB_KERBEROS_OPTIONS
        = new HashMap<String, String>();
    static {
      if (IBM_JAVA) {
        KEYTAB_KERBEROS_OPTIONS.put("credsType", "both");
        KEYTAB_KERBEROS_OPTIONS.put("useKeytab",
            prependFileAuthority(keytabFile));
      } else {
        KEYTAB_KERBEROS_OPTIONS.put("doNotPrompt", "true");
        KEYTAB_KERBEROS_OPTIONS.put("useKeyTab", "true");
        KEYTAB_KERBEROS_OPTIONS.put("storeKey", "true");
        KEYTAB_KERBEROS_OPTIONS.put("keyTab", keytabFile);
      }
      KEYTAB_KERBEROS_OPTIONS.put("principal", keytabPrincipal);
      KEYTAB_KERBEROS_OPTIONS.put("refreshKrb5Config", "true");
      KEYTAB_KERBEROS_OPTIONS.put("debug", "false");
    }

    private static final AppConfigurationEntry USER_KERBEROS_LOGIN =
      new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(),
                                AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,
                                KEYTAB_KERBEROS_OPTIONS);

    private static final AppConfigurationEntry[] USER_KERBEROS_CONF =
      new AppConfigurationEntry[]{OS_SPECIFIC_LOGIN, USER_KERBEROS_LOGIN};

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
      return USER_KERBEROS_CONF;
    }

    private static String prependFileAuthority(String keytabPath) {
      return keytabPath.startsWith("file://") ? keytabPath
          : "file://" + keytabPath;
    }
  }
  
  private URL url;
  private HttpURLConnection conn;
  private Base64 base64;
  private ConnectionConfigurator connConfigurator;

  /**
   * Sets a {@link ConnectionConfigurator} instance to use for
   * configuring connections.
   *
   * @param configurator the {@link ConnectionConfigurator} instance.
   */
  @Override
  public void setConnectionConfigurator(ConnectionConfigurator configurator) {
    connConfigurator = configurator;
  }

  /**
   * Performs SPNEGO authentication against the specified URL.
   * <p>
   * If a token is given it does a NOP and returns the given token.
   * <p>
   * If no token is given, it will perform the SPNEGO authentication sequence using an
   * HTTP <code>OPTIONS</code> request.
   *
   * @param url the URl to authenticate against.
   * @param token the authentication token being used for the user.
   *
   * @throws IOException if an IO error occurred.
   * @throws AuthenticationException if an authentication error occurred.
   */
  @Override
  public void authenticate(URL url, AuthenticatedURL.Token token)
    throws IOException, AuthenticationException {

    if (!token.isSet()) {
      this.url = url;
      base64 = new Base64(0);
      conn = (HttpURLConnection) url.openConnection();
      if (connConfigurator != null) {
        conn = connConfigurator.configure(conn);
      }
      conn.setRequestMethod(AUTH_HTTP_METHOD);
      conn.connect();
      
      boolean needFallback = false;
      if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
        LOG.debug("JDK performed authentication on our behalf.");
        // If the JDK already did the SPNEGO back-and-forth for
        // us, just pull out the token.
        AuthenticatedURL.extractToken(conn, token);
        if (isTokenKerberos(token)) {
          return;
        }
        needFallback = true;
      }
      if (!needFallback && isNegotiate()) {
        LOG.debug("Performing our own SPNEGO sequence.");
        doSpnegoSequence(token);
      } else {
        throw new IOException("Should perform our own SPNEGO sequence");
      }
    }
  }

  public void setKeyTab(String keytabFile, String keytabPrincipal) {
    this.keytabFile = keytabFile;
    this.keytabPrincipal = keytabPrincipal;
  }

  /*
   * Check if the passed token is of type "kerberos" or "kerberos-dt"
   */
  private boolean isTokenKerberos(AuthenticatedURL.Token token)
      throws AuthenticationException {
    if (token.isSet()) {
      AuthToken aToken = AuthToken.parse(token.toString());
      if (aToken.getType().equals("kerberos")
          || aToken.getType().equals("kerberos-dt")) {
        return true;
      }
    }
    return false;
  }

  /*
  * Indicates if the response is starting a SPNEGO negotiation.
  */
  private boolean isNegotiate() throws IOException {
    boolean negotiate = false;
    if (conn.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      String authHeader = conn.getHeaderField(WWW_AUTHENTICATE);
      negotiate = authHeader != null && authHeader.trim().startsWith(NEGOTIATE);
    }
    return negotiate;
  }

  /**
   * Implements the SPNEGO authentication sequence interaction using the current default principal
   * in the Kerberos cache (normally set via kinit).
   *
   * @param token the authentication token being used for the user.
   *
   * @throws IOException if an IO error occurred.
   * @throws AuthenticationException if an authentication error occurred.
   */
  private void doSpnegoSequence(AuthenticatedURL.Token token) throws IOException, AuthenticationException {
    try {
      AccessControlContext context = AccessController.getContext();
      Subject subject = Subject.getSubject(context);
      if (subject == null
          || (subject.getPrivateCredentials(KerberosKey.class).isEmpty()
              && subject.getPrivateCredentials(KerberosTicket.class).isEmpty())) {
        LOG.debug("No subject in context, logging in");
        subject = new Subject();
        LoginContext login = new LoginContext("", subject,
            null, new KerberosConfiguration());
        login.login();
      }

      if (LOG.isDebugEnabled()) {
        LOG.debug("Using subject: " + subject);
      }
      Subject.doAs(subject, new PrivilegedExceptionAction<Void>() {

        @Override
        public Void run() throws Exception {
          GSSContext gssContext = null;
          try {
            GSSManager gssManager = GSSManager.getInstance();
            String servicePrincipal = KerberosUtil.getServicePrincipal("HTTP",
                KerberosAuthenticator.this.url.getHost());
            LOG.info("service principal is:" + servicePrincipal);
            Oid oid = KerberosUtil.getOidInstance("NT_GSS_KRB5_PRINCIPAL");
            GSSName serviceName = gssManager.createName(servicePrincipal,
                                                        oid);
            oid = KerberosUtil.getOidInstance("GSS_KRB5_MECH_OID");
            gssContext = gssManager.createContext(serviceName, oid, null,
                                                  GSSContext.DEFAULT_LIFETIME);
            gssContext.requestCredDeleg(true);
            gssContext.requestMutualAuth(true);

            byte[] inToken = new byte[0];
            byte[] outToken;
            boolean established = false;

            // Loop while the context is still not established
            while (!established) {
              outToken = gssContext.initSecContext(inToken, 0, inToken.length);
              if (outToken != null) {
                sendToken(outToken);
              }

              if (!gssContext.isEstablished()) {
                inToken = readToken();
              } else {
                established = true;
              }
            }
          } finally {
            if (gssContext != null) {
              gssContext.dispose();
              gssContext = null;
            }
          }
          return null;
        }
      });
    } catch (PrivilegedActionException ex) {
      throw new AuthenticationException(ex.getException());
    } catch (LoginException ex) {
      throw new AuthenticationException(ex);
    }
    AuthenticatedURL.extractToken(conn, token);
  }

  /*
  * Sends the Kerberos token to the server.
  */
  private void sendToken(byte[] outToken) throws IOException {
    String token = base64.encodeToString(outToken);
    conn = (HttpURLConnection) url.openConnection();
    if (connConfigurator != null) {
      conn = connConfigurator.configure(conn);
    }
    conn.setRequestMethod(AUTH_HTTP_METHOD);
    conn.setRequestProperty(AUTHORIZATION, NEGOTIATE + " " + token);
    conn.connect();
  }

  /*
  * Retrieves the Kerberos token returned by the server.
  */
  private byte[] readToken() throws IOException, AuthenticationException {
    int status = conn.getResponseCode();
    if (status == HttpURLConnection.HTTP_OK || status == HttpURLConnection.HTTP_UNAUTHORIZED) {
      String authHeader = conn.getHeaderField(WWW_AUTHENTICATE);
      if (authHeader == null || !authHeader.trim().startsWith(NEGOTIATE)) {
        throw new AuthenticationException("Invalid SPNEGO sequence, '" + WWW_AUTHENTICATE
            + "' header incorrect: " + authHeader);
      }
      String negotiation = authHeader.trim().substring((NEGOTIATE + " ").length()).trim();
      return base64.decode(negotiation);
    }
    throw new AuthenticationException("Invalid SPNEGO sequence, status code: " + status);
  }

}
