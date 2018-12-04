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
package org.apache.kerby.has.common.ssl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.util.StringUtils;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.text.MessageFormat;

/**
 * Borrow the class from Apache Hadoop
 */

/**
 * Interface that gives access to {@link KeyManager} and {@link TrustManager}
 * implementations.
 */
@InterfaceAudience.Private
@InterfaceStability.Evolving
public class KeyStoresFactory extends KrbConfig {

  private static final Log LOG =
    LogFactory.getLog(KeyStoresFactory.class);

  public static final String SSL_KEYSTORE_LOCATION_TPL_KEY =
    "ssl.{0}.keystore.location";
  public static final String SSL_KEYSTORE_PASSWORD_TPL_KEY =
    "ssl.{0}.keystore.password";
  public static final String SSL_KEYSTORE_KEYPASSWORD_TPL_KEY =
    "ssl.{0}.keystore.keypassword";
  public static final String SSL_KEYSTORE_TYPE_TPL_KEY =
    "ssl.{0}.keystore.type";

  public static final String SSL_TRUSTSTORE_RELOAD_INTERVAL_TPL_KEY =
    "ssl.{0}.truststore.reload.interval";
  public static final String SSL_TRUSTSTORE_LOCATION_TPL_KEY =
    "ssl.{0}.truststore.location";
  public static final String SSL_TRUSTSTORE_PASSWORD_TPL_KEY =
    "ssl.{0}.truststore.password";
  public static final String SSL_TRUSTSTORE_TYPE_TPL_KEY =
    "ssl.{0}.truststore.type";

  /**
   * Default format of the keystore files.
   */
  public static final String DEFAULT_KEYSTORE_TYPE = "jks";

  /**
   * Reload interval in milliseconds.
   */
  public static final long DEFAULT_SSL_TRUSTSTORE_RELOAD_INTERVAL = 10000;

  private HasConfig conf;
  private KeyManager[] keyManagers;
  private TrustManager[] trustManagers;
  private ReloadingX509TrustManager trustManager;

  /**
   * Sets the configuration for the factory.
   *
   * @param conf the configuration for the factory.
   */
  public void setConf(HasConfig conf) {
    this.conf = conf;
  }

  /**
   * Returns the configuration of the factory.
   *
   * @return the configuration of the factory.
   */
  public HasConfig getConf() {
    return conf;
  }


  /**
   * Initializes the keystores of the factory.
   *
   * @param mode if the keystores are to be used in client or server mode.
   * @throws IOException thrown if the keystores could not be initialized due
   * to an IO error.
   * @throws GeneralSecurityException thrown if the keystores could not be
   * initialized due to an security error.
   */
  public void init(SSLFactory.Mode mode) throws IOException, GeneralSecurityException {
     boolean requireClientCert =
      conf.getBoolean(SSLFactory.SSL_REQUIRE_CLIENT_CERT_KEY,
          SSLFactory.DEFAULT_SSL_REQUIRE_CLIENT_CERT);

    // certificate store
    String keystoreType =
      conf.getString(resolvePropertyName(mode, SSL_KEYSTORE_TYPE_TPL_KEY),
               DEFAULT_KEYSTORE_TYPE);
    KeyStore keystore = KeyStore.getInstance(keystoreType);
    String keystoreKeyPassword = null;
    if (requireClientCert || mode == SSLFactory.Mode.SERVER) {
      String locationProperty =
        resolvePropertyName(mode, SSL_KEYSTORE_LOCATION_TPL_KEY);
      String keystoreLocation = conf.getString(locationProperty, "");
      if (keystoreLocation.isEmpty()) {
        throw new GeneralSecurityException("The property '" + locationProperty
            + "' has not been set in the ssl configuration file.");
      }
      String passwordProperty =
        resolvePropertyName(mode, SSL_KEYSTORE_PASSWORD_TPL_KEY);
      String keystorePassword = getPassword(conf, passwordProperty, "");
      if (keystorePassword.isEmpty()) {
        throw new GeneralSecurityException("The property '" + passwordProperty
            + "' has not been set in the ssl configuration file.");
      }
      String keyPasswordProperty =
        resolvePropertyName(mode, SSL_KEYSTORE_KEYPASSWORD_TPL_KEY);
      // Key password defaults to the same value as store password for
      // compatibility with legacy configurations that did not use a separate
      // configuration property for key password.
      keystoreKeyPassword = getPassword(
          conf, keyPasswordProperty, keystorePassword);
      LOG.debug(mode.toString() + " KeyStore: " + keystoreLocation);

      InputStream is = new FileInputStream(keystoreLocation);
      try {
        keystore.load(is, keystorePassword.toCharArray());
      } finally {
        is.close();
      }
      LOG.debug(mode.toString() + " Loaded KeyStore: " + keystoreLocation);
    } else {
      keystore.load(null, null);
    }
    KeyManagerFactory keyMgrFactory = KeyManagerFactory
        .getInstance(SSLFactory.SSLCERTIFICATE);

    keyMgrFactory.init(keystore, (keystoreKeyPassword != null)
        ? keystoreKeyPassword.toCharArray() : null);
    keyManagers = keyMgrFactory.getKeyManagers();

    //trust store
    String truststoreType =
      conf.getString(resolvePropertyName(mode, SSL_TRUSTSTORE_TYPE_TPL_KEY),
               DEFAULT_KEYSTORE_TYPE);

    String locationProperty =
      resolvePropertyName(mode, SSL_TRUSTSTORE_LOCATION_TPL_KEY);
    String truststoreLocation = conf.getString(locationProperty, "");
    if (!truststoreLocation.isEmpty()) {
      String passwordProperty = resolvePropertyName(mode,
          SSL_TRUSTSTORE_PASSWORD_TPL_KEY);
      String truststorePassword = getPassword(conf, passwordProperty, "");
      if (truststorePassword.isEmpty()) {
        throw new GeneralSecurityException("The property '" + passwordProperty
            + "' has not been set in the ssl configuration file.");
      }
      long truststoreReloadInterval =
          conf.getLong(resolvePropertyName(mode, SSL_TRUSTSTORE_RELOAD_INTERVAL_TPL_KEY),
              DEFAULT_SSL_TRUSTSTORE_RELOAD_INTERVAL);

      LOG.debug(mode.toString() + " TrustStore: " + truststoreLocation);

      trustManager = new ReloadingX509TrustManager(truststoreType,
          truststoreLocation,
          truststorePassword,
          truststoreReloadInterval);
      trustManager.init();
      LOG.debug(mode.toString() + " Loaded TrustStore: " + truststoreLocation);
      trustManagers = new TrustManager[]{trustManager};
    } else {
      LOG.debug("The property '" + locationProperty + "' has not been set, "
          + "no TrustStore will be loaded");
      trustManagers = null;
    }
  }

  String getPassword(HasConfig conf, String alias, String defaultPass) {
    String password = defaultPass;
    password = conf.getString(alias);
    return password;
  }

  /**
   * Releases any resources being used.
   */
  public void destroy() {
    if (trustManager != null) {
      trustManager.destroy();
      trustManager = null;
      keyManagers = null;
      trustManagers = null;
    }
  }

  /**
   * Returns the keymanagers for owned certificates.
   *
   * @return the keymanagers for owned certificates.
   */
  public KeyManager[] getKeyManagers() {
    return keyManagers;
  }

  /**
   * Returns the trustmanagers for trusted certificates.
   *
   * @return the trustmanagers for trusted certificates.
   */
  public TrustManager[] getTrustManagers() {
    return trustManagers;
  }

  /**
   * Resolves a property name to its client/server version if applicable.
   *
   * NOTE: This method is public for testing purposes.
   *
   * @param mode client/server mode.
   * @param template property name template.
   * @return the resolved property name.
   */
  public static String resolvePropertyName(SSLFactory.Mode mode,
                                           String template) {
    return MessageFormat.format(
        template, StringUtils.toLowerCase(mode.toString()));
  }
}
