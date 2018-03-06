/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kerby.has.common.util;

import org.apache.hadoop.classification.InterfaceStability;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.spnego.AuthenticatedURL;
import org.apache.kerby.has.common.spnego.AuthenticationException;
import org.apache.kerby.has.common.spnego.KerberosHasAuthenticator;
import org.apache.kerby.has.common.ssl.SSLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;

/**
 * Borrow the class from Apache Hadoop
 */

/**
 * Utilities for handling URLs
 */
@InterfaceStability.Unstable
public class URLConnectionFactory {
  private static final Logger LOG = LoggerFactory
      .getLogger(URLConnectionFactory.class);

  /**
   * Timeout for socket connects and reads
   */
   // 1 minute
  public static final int DEFAULT_SOCKET_TIMEOUT = 60 * 1000;
  private final ConnectionConfigurator connConfigurator;

  private static final ConnectionConfigurator DEFAULT_TIMEOUT_CONN_CONFIGURATOR
      = new ConnectionConfigurator() {
        @Override
        public HttpURLConnection configure(HttpURLConnection conn)
            throws IOException {
          URLConnectionFactory.setTimeouts(conn,
                                           DEFAULT_SOCKET_TIMEOUT,
                                           DEFAULT_SOCKET_TIMEOUT);
          return conn;
        }
      };

  /**
   * The URLConnectionFactory that sets the default timeout and it only trusts
   * Java's SSL certificates.
   */
  public static final URLConnectionFactory DEFAULT_SYSTEM_CONNECTION_FACTORY =
      new URLConnectionFactory(DEFAULT_TIMEOUT_CONN_CONFIGURATOR);

  /**
   * Construct a new URLConnectionFactory based on the configuration. It will
   * try to load SSL certificates when it is specified.
   */
  public static URLConnectionFactory newDefaultURLConnectionFactory(HasConfig conf) {
    ConnectionConfigurator conn = null;
    try {
      conn = newSslConnConfigurator(DEFAULT_SOCKET_TIMEOUT, conf);
    } catch (Exception e) {
      LOG.debug(
          "Cannot load customized ssl related configuration. Fallback to system-generic settings.",
          e);
      conn = DEFAULT_TIMEOUT_CONN_CONFIGURATOR;
    }
    return new URLConnectionFactory(conn);
  }

  URLConnectionFactory(ConnectionConfigurator connConfigurator) {
    this.connConfigurator = connConfigurator;
  }

  /**
   * Create a new ConnectionConfigurator for SSL connections
   */
  private static ConnectionConfigurator newSslConnConfigurator(
      final int defaultTimeout, HasConfig conf)
      throws IOException, GeneralSecurityException, HasException {
    final SSLFactory factory;
    final SSLSocketFactory sf;
    final HostnameVerifier hv;
    final int connectTimeout;
    final int readTimeout;

    factory = new SSLFactory(SSLFactory.Mode.CLIENT, conf);
    factory.init();
    sf = factory.createSSLSocketFactory();
    hv = factory.getHostnameVerifier();

    connectTimeout = defaultTimeout;

    readTimeout = defaultTimeout;

    return new ConnectionConfigurator() {
      @Override
      public HttpURLConnection configure(HttpURLConnection conn)
          throws IOException {
        if (conn instanceof HttpsURLConnection) {
          HttpsURLConnection c = (HttpsURLConnection) conn;
          c.setSSLSocketFactory(sf);
          c.setHostnameVerifier(hv);
        }
        URLConnectionFactory.setTimeouts(conn, connectTimeout, readTimeout);
        return conn;
      }
    };
  }

  /**
   * Opens a url with read and connect timeouts
   *
   * @param url
   *          to open
   * @return URLConnection
   * @throws IOException
   */
  public URLConnection openConnection(URL url) throws IOException {
    try {
      return openConnection(url, false, null);
    } catch (AuthenticationException e) {
      // Unreachable
      LOG.error("Open connection {} failed", url, e);
      return null;
    }
  }

  /**
   * Opens a url with read and connect timeouts
   *
   * @param url
   *          URL to open
   * @param isSpnego
   *          whether the url should be authenticated via SPNEGO
   * @return URLConnection
   * @throws IOException
   * @throws AuthenticationException
   */
  public URLConnection openConnection(URL url, boolean isSpnego, HasConfig hasConfig)
      throws IOException, AuthenticationException {
    if (isSpnego && hasConfig != null) {
      LOG.debug("open AuthenticatedURL connection {}", url);
      final AuthenticatedURL.Token authToken = new AuthenticatedURL.Token();
      return new AuthenticatedURL(new KerberosHasAuthenticator(hasConfig.getAdminKeytab(),
          hasConfig.getAdminKeytabPrincipal()),
          connConfigurator).openConnection(url, authToken);
    } else {
      LOG.debug("open URL connection");
      URLConnection connection = url.openConnection();
      if (connection instanceof HttpURLConnection) {
        connConfigurator.configure((HttpURLConnection) connection);
      }
      return connection;
    }
  }

  /**
   * Sets timeout parameters on the given URLConnection.
   *
   * @param connection
   *          URLConnection to set
   * @param connectTimeout
   *          the connection and read timeout of the connection.
   */
  private static void setTimeouts(URLConnection connection,
                                  int connectTimeout,
                                  int readTimeout) {
    connection.setConnectTimeout(connectTimeout);
    connection.setReadTimeout(readTimeout);
  }
}
