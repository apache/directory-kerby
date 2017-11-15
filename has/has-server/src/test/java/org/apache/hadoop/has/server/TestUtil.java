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
package org.apache.hadoop.has.server;

import org.apache.hadoop.has.common.HasConfig;
import org.apache.hadoop.has.server.web.WebConfigKey;
import org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

class TestUtil {

  /**
   * system property for test data: {@value}
   */
  private static final String SYSPROP_TEST_DATA_DIR = "test.build.data";

  /**
   * The default path for using in Hadoop path references: {@value}
   */
  private static final String DEFAULT_TEST_DATA_PATH = "target/";

  /**
   * Get a temp path. This may or may not be relative; it depends on what the
   * {@link #SYSPROP_TEST_DATA_DIR} is set to. If unset, it returns a path
   * under the relative path {@link #DEFAULT_TEST_DATA_PATH}
   *
   * @param subPath sub path, with no leading "/" character
   * @return a string to use in paths
   */
  public static String getTempPath(String subPath) {
    String prop = System.getProperty(SYSPROP_TEST_DATA_DIR, DEFAULT_TEST_DATA_PATH);
    if (prop.isEmpty()) {
      // corner case: property is there but empty
      prop = DEFAULT_TEST_DATA_PATH;
    }
    if (!prop.endsWith("/")) {
      prop = prop + "/";
    }
    return prop + subPath;
  }

  public static String getClasspathDir(Class testClass) throws Exception {
    String file = testClass.getName();
    file = file.replace('.', '/') + ".class";
    URL url = Thread.currentThread().getContextClassLoader().getResource(file);
    String baseDir = url.toURI().getPath();
    baseDir = baseDir.substring(0, baseDir.length() - file.length() - 1);
    return baseDir;
  }

  @SuppressWarnings("deprecation")
  /*
   * Create a self-signed X.509 Certificate.
   *
   * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
   * @param pair the KeyPair
   * @param days how many days from now the Certificate is valid for
   * @param algorithm the signing algorithm, eg "SHA1withRSA"
   * @return the self-signed certificate
   */
  private static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
      throws CertificateEncodingException, InvalidKeyException, IllegalStateException,
      NoSuchProviderException, NoSuchAlgorithmException, SignatureException {

    Date from = new Date();
    Date to = new Date(from.getTime() + days * 86400000L);
    BigInteger sn = new BigInteger(64, new SecureRandom());
    X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
    X500Principal dnName = new X500Principal(dn);

    certGen.setSerialNumber(sn);
    certGen.setIssuerDN(dnName);
    certGen.setNotBefore(from);
    certGen.setNotAfter(to);
    certGen.setSubjectDN(dnName);
    certGen.setPublicKey(pair.getPublic());
    certGen.setSignatureAlgorithm(algorithm);

    return certGen.generate(pair.getPrivate());
  }

  private static KeyPair generateKeyPair(String algorithm) throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
    keyGen.initialize(1024);
    return keyGen.genKeyPair();
  }

  private static KeyStore createEmptyKeyStore() throws GeneralSecurityException, IOException {
    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(null, null); // initialize
    return ks;
  }

  private static void saveKeyStore(KeyStore ks, String filename, String password)
      throws GeneralSecurityException, IOException {
    FileOutputStream out = new FileOutputStream(filename);
    ks.store(out, password.toCharArray());
    out.close();
  }

  private static void createKeyStore(String filename, String password, String alias, Key privateKey, Certificate cert)
      throws GeneralSecurityException, IOException {
    KeyStore ks = createEmptyKeyStore();
    ks.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{cert});
    saveKeyStore(ks, filename, password);
  }

  private static <T extends Certificate> void createTrustStore(String filename, String password, Map<String, T> certs)
      throws GeneralSecurityException, IOException {
    KeyStore ks = createEmptyKeyStore();
    for (Map.Entry<String, T> cert : certs.entrySet()) {
      ks.setCertificateEntry(cert.getKey(), cert.getValue());
    }
    saveKeyStore(ks, filename, password);
  }

  /**
   * Performs complete setup of SSL configuration in preparation for testing an
   * SSLFactory.  This includes keys, certs, keystore, truststore, the server
   * SSL configuration file, the client SSL configuration file, and the master
   * configuration file read by the SSLFactory.
   *
   * @param keystoreDir   String directory to save keystore
   * @param sslConfDir    String directory to save SSL configuration files
   * @param conf          Configuration master configuration to be used by an SSLFactory,
   *                      which will be mutated by this method
   * @param useClientCert boolean true to make the client present a cert in the SSL handshake
   */
  public static void setupSSLConfig(String keystoreDir, String sslConfDir, HasConfig conf, boolean useClientCert)
      throws Exception {
    setupSSLConfig(keystoreDir, sslConfDir, conf, useClientCert, true, "");
  }

  /**
   * Performs complete setup of SSL configuration in preparation for testing an
   * SSLFactory.  This includes keys, certs, keystore, truststore, the server
   * SSL configuration file, the client SSL configuration file, and the master
   * configuration file read by the SSLFactory.
   *
   * @param keystoreDir   String directory to save keystore
   * @param sslConfDir    String directory to save SSL configuration files
   * @param conf          Configuration master configuration to be used by an SSLFactory,
   *                      which will be mutated by this method
   * @param useClientCert boolean true to make the client present a cert in the SSL handshake
   * @param trustStore    boolean true to create truststore, false not to create it
   * @param excludeCiphers String comma separated ciphers to exclude
   * @throws Exception e
   */
  private static void setupSSLConfig(String keystoreDir, String sslConfDir, HasConfig conf, boolean useClientCert,
                                     boolean trustStore, String excludeCiphers) throws Exception {
    String clientKS = keystoreDir + "/clientKS.jks";
    String clientPassword = "clientP";
    String serverKS = keystoreDir + "/serverKS.jks";
    String serverPassword = "serverP";
    String trustKS = null;
    String trustPassword = "trustP";

    File sslClientConfFile = new File(sslConfDir, getClientSSLConfigFileName());
    File sslServerConfFile = new File(sslConfDir, getServerSSLConfigFileName());

    Map<String, X509Certificate> certs = new HashMap<String, X509Certificate>();

    if (useClientCert) {
      KeyPair cKP = TestUtil.generateKeyPair("RSA");
      X509Certificate cCert = TestUtil.generateCertificate("CN=localhost, O=client", cKP, 30, "SHA1withRSA");
      TestUtil.createKeyStore(clientKS, clientPassword, "client", cKP.getPrivate(), cCert);
      certs.put("client", cCert);
    }

    KeyPair sKP = TestUtil.generateKeyPair("RSA");
    X509Certificate sCert = TestUtil.generateCertificate("CN=localhost, O=server", sKP, 30, "SHA1withRSA");
    TestUtil.createKeyStore(serverKS, serverPassword, "server", sKP.getPrivate(), sCert);
    certs.put("server", sCert);

    if (trustStore) {
      trustKS = keystoreDir + "/trustKS.jks";
      TestUtil.createTrustStore(trustKS, trustPassword, certs);
    }

    HasConfig clientSSLConf = createClientSSLConfig(clientKS, clientPassword, clientPassword, trustKS, excludeCiphers);
    HasConfig serverSSLConf = createServerSSLConfig(serverKS, serverPassword, serverPassword, trustKS, excludeCiphers);

    saveConfig(sslClientConfFile, clientSSLConf);
    saveConfig(sslServerConfFile, serverSSLConf);

    conf.setString(SSLFactory.SSL_HOSTNAME_VERIFIER_KEY, "ALLOW_ALL");
    conf.setString(SSLFactory.SSL_CLIENT_CONF_KEY, sslClientConfFile.getCanonicalPath());
    conf.setString(SSLFactory.SSL_SERVER_CONF_KEY, sslServerConfFile.getCanonicalPath());
    conf.setString(WebConfigKey.HAS_SERVER_HTTPS_KEYSTORE_RESOURCE_KEY, sslServerConfFile.getAbsolutePath());
    conf.setBoolean(SSLFactory.SSL_REQUIRE_CLIENT_CERT_KEY, useClientCert);
  }

  /**
   * Create SSL configuration for a client.
   *
   * @param clientKS       String client keystore file
   * @param password       String store password, or null to avoid setting store password
   * @param keyPassword    String key password, or null to avoid setting key password
   * @param trustKS        String truststore file
   * @param excludeCiphers String comma separated ciphers to exclude
   * @return Configuration for client SSL
   */
  private static HasConfig createClientSSLConfig(String clientKS, String password, String keyPassword,
                                                 String trustKS, String excludeCiphers) {
    return createSSLConfig(SSLFactory.Mode.CLIENT, clientKS, password, keyPassword, trustKS, excludeCiphers);
  }

  /**
   * Creates SSL configuration for a server.
   *
   * @param serverKS       String server keystore file
   * @param password       String store password, or null to avoid setting store password
   * @param keyPassword    String key password, or null to avoid setting key password
   * @param trustKS        String truststore file
   * @param excludeCiphers String comma separated ciphers to exclude
   * @return HasConfig
   * @throws IOException e
   */
  private static HasConfig createServerSSLConfig(String serverKS, String password, String keyPassword,
                                                 String trustKS, String excludeCiphers) throws IOException {
    return createSSLConfig(SSLFactory.Mode.SERVER, serverKS, password, keyPassword, trustKS, excludeCiphers);
  }

  /**
   * Returns the client SSL configuration file name.  Under parallel test
   * execution, this file name is parametrized by a unique ID to ensure that
   * concurrent tests don't collide on an SSL configuration file.
   *
   * @return client SSL configuration file name
   */
  private static String getClientSSLConfigFileName() {
    return getSSLConfigFileName("ssl-client");
  }

  /**
   * Returns the server SSL configuration file name.  Under parallel test
   * execution, this file name is parametrized by a unique ID to ensure that
   * concurrent tests don't collide on an SSL configuration file.
   *
   * @return client SSL configuration file name
   */
  private static String getServerSSLConfigFileName() {
    return getSSLConfigFileName("ssl-server");
  }

  /**
   * Returns an SSL configuration file name.  Under parallel test
   * execution, this file name is parametrized by a unique ID to ensure that
   * concurrent tests don't collide on an SSL configuration file.
   *
   * @param base the base of the file name
   * @return SSL configuration file name for base
   */
  private static String getSSLConfigFileName(String base) {
    String testUniqueForkId = System.getProperty("test.unique.fork.id");
    String fileSuffix = testUniqueForkId != null ? "-" + testUniqueForkId : "";
    return base + fileSuffix + ".xml";
  }

  /**
   * Creates SSL configuration.
   *
   * @param mode        SSLFactory.Mode mode to configure
   * @param keystore    String keystore file
   * @param password    String store password, or null to avoid setting store password
   * @param keyPassword String key password, or null to avoid setting key password
   * @param trustKS     String truststore file
   * @return Configuration for SSL
   */
  private static HasConfig createSSLConfig(SSLFactory.Mode mode, String keystore, String password,
                                           String keyPassword, String trustKS, String excludeCiphers) {
    String trustPassword = "trustP";

    HasConfig sslConf = new HasConfig();
    if (keystore != null) {
      sslConf.setString(FileBasedKeyStoresFactory.resolvePropertyName(mode,
          FileBasedKeyStoresFactory.SSL_KEYSTORE_LOCATION_TPL_KEY), keystore);
    }
    if (password != null) {
      sslConf.setString(FileBasedKeyStoresFactory.resolvePropertyName(mode,
          FileBasedKeyStoresFactory.SSL_KEYSTORE_PASSWORD_TPL_KEY), password);
    }
    if (keyPassword != null) {
      sslConf.setString(FileBasedKeyStoresFactory.resolvePropertyName(mode,
          FileBasedKeyStoresFactory.SSL_KEYSTORE_KEYPASSWORD_TPL_KEY),
          keyPassword);
    }
    if (trustKS != null) {
      sslConf.setString(FileBasedKeyStoresFactory.resolvePropertyName(mode,
          FileBasedKeyStoresFactory.SSL_TRUSTSTORE_LOCATION_TPL_KEY), trustKS);
    }
    if (trustPassword != null) {
      sslConf.setString(FileBasedKeyStoresFactory.resolvePropertyName(mode,
          FileBasedKeyStoresFactory.SSL_TRUSTSTORE_PASSWORD_TPL_KEY),
          trustPassword);
    }
    if (null != excludeCiphers && !excludeCiphers.isEmpty()) {
      sslConf.setString(FileBasedKeyStoresFactory.resolvePropertyName(mode,
          FileBasedKeyStoresFactory.SSL_EXCLUDE_CIPHER_LIST),
          excludeCiphers);
    }
    sslConf.setString(FileBasedKeyStoresFactory.resolvePropertyName(mode,
        FileBasedKeyStoresFactory.SSL_TRUSTSTORE_RELOAD_INTERVAL_TPL_KEY), "1000");

    return sslConf;
  }

  /**
   * Saves configuration to a file.
   *
   * @param file File to save
   * @param conf Configuration contents to write to file
   * @throws IOException if there is an I/O error saving the file
   */
  private static void saveConfig(File file, HasConfig conf) throws IOException {
    OutputStream output = new FileOutputStream(file);
    Properties prop = new Properties();

    // set the properties value
    for (String name : conf.getNames()) {
      prop.setProperty(name, conf.getString(name));
    }

    // save properties to project root folder
    prop.store(output, null);
  }
}
