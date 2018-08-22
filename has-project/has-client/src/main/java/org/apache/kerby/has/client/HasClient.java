/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.client;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.CharacterPredicates;
import org.apache.commons.text.RandomStringGenerator;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasConfigKey;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.ssl.SSLFactory;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.common.util.URLConnectionFactory;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.util.IOUtil;
import org.apache.kerby.util.SysUtil;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * HAS client
 */
public class HasClient {

    public static final Logger LOG = LoggerFactory.getLogger(HasClient.class);

    public static final String JAVA_SECURITY_KRB5_CONF = "java.security.krb5.conf";
    public static final String HAS_HTTP_PORT_DEFAULT = "9870";
    public static final String HAS_CONFIG_DEFAULT = "/etc/has/has-client.conf";
    public static final String CA_ROOT_DEFAULT = "/etc/has/ca-root.pem";

    private String hadoopSecurityHas = null;
    private String type;
    private File clientConfigFolder;


    public HasClient() { }

    /**
     * Create an instance of the HasClient.
     *
     * @param hadoopSecurityHas the has config
     */
    public HasClient(String hadoopSecurityHas) {
        this.hadoopSecurityHas = hadoopSecurityHas;
    }


    public TgtTicket requestTgt() throws HasException {
        HasConfig config;
        if (hadoopSecurityHas == null) {
            String hasClientConf = System.getenv("HAS_CLIENT_CONF");
            if (hasClientConf == null) {
                hasClientConf = HAS_CONFIG_DEFAULT;
            }
            LOG.debug("has-client conf path: " + hasClientConf);
            File confFile = new File(hasClientConf);
            if (!confFile.exists()) {
                LOG.warn("The HAS client config file: " + hasClientConf + " does not exist.");
                throw new HasException("The HAS client config file: " + hasClientConf
                    + " does not exist.");
            }
            try {
                config = HasUtil.getHasConfig(confFile);
            } catch (HasException e) {
                LOG.error("Failed to get has client config: " + e.getMessage());
                throw new HasException("Failed to get has client config: " + e.getMessage());
            }
        } else {
            config = new HasConfig();
            String[] urls = hadoopSecurityHas.split(";");
            StringBuilder host = new StringBuilder();
            int port = 0;
            try {
                for (String url : urls) {
                    URI uri = new URI(url.trim());

                    // parse host
                    host.append(uri.getHost()).append(",");

                    // parse port
                    if (port == 0) {
                        port = uri.getPort();
                    } else {
                        if (port != uri.getPort()) {
                            throw new HasException("Invalid port: not even.");
                        }
                    }

                    // We will get the auth type from env first
                    type = System.getenv("auth_type");
                    // parse host
                    if (type == null) {
                        String[] strs = uri.getQuery().split("=");
                        if (strs[0].equals("auth_type")) {
                            type = strs[1];
                        } else {
                            LOG.warn("No auth type in conf.");
                        }
                    }
                }
                if (host.length() == 0 || port == 0) {
                    throw new HasException("host is null.");
                } else {
                    config.setString(HasConfigKey.HTTPS_HOST,  host.subSequence(0, host.length() - 1).toString());
                    config.setInt(HasConfigKey.HTTPS_PORT, port);
                    config.setString(HasConfigKey.AUTH_TYPE, type);
                }
            } catch (URISyntaxException e) {
                LOG.error("Errors occurred when getting web url. " + e.getMessage());
                throw new HasException(
                    "Errors occurred when getting web url. " + e.getMessage());
            }
        }
        if (config == null) {
            throw new HasException("Failed to get HAS client config.");
        }
        clientConfigFolder = new File("/etc/has/" + config.getHttpsHost());
        if (!clientConfigFolder.exists()) {
            clientConfigFolder.mkdirs();
        }

        // get and set ssl-client/trustStore first
        String sslClientConfPath = clientConfigFolder + "/ssl-client.conf";
        loadSslClientConf(config, sslClientConfPath);
        config.setString(HasConfigKey.SSL_CLIENT_CONF, sslClientConfPath);

        HasClientPlugin plugin;
        try {
            plugin = getClientTokenPlugin(config);
        } catch (HasException e) {
            LOG.error("Failed to get client token plugin from config: " + e.getMessage());
            throw new HasException(
                "Failed to get client token plugin from config: " + e.getMessage());
        }
        AuthToken authToken;
        try {
            authToken = plugin.login(config);
        } catch (HasLoginException e) {
            LOG.error(e.getMessage());
            throw new HasException(e.getMessage());
        }
        type = plugin.getLoginType();

        return requestTgt(authToken, type, config);
    }

    private HasClientPlugin getClientTokenPlugin(HasConfig config) throws HasException {
        String pluginName = config.getPluginName();
        HasClientPlugin clientPlugin;
        if (pluginName != null) {
            clientPlugin = HasClientPluginRegistry.createPlugin(pluginName);
        } else {
            LOG.debug("Please set the plugin name in has client conf");
            throw new HasException("Please set the plugin name in has client conf");
        }

        return clientPlugin;
    }

    /**
     * Request a TGT with user token, plugin type and has config.
     * @param authToken
     * @param type
     * @param config
     * @return TGT
     * @throws HasException e
     */
    public TgtTicket requestTgt(AuthToken authToken, String type, HasConfig config)
        throws HasException {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();

        String tokenString;
        try {
            tokenString = tokenEncoder.encodeAsString(authToken);
        } catch (KrbException e) {
            LOG.debug("Failed to decode the auth token. " + e.getMessage());
            throw new HasException("Failed to decode the auth token. " + e.getMessage());
        }

        JSONObject json = null;
        int responseStatus = 0;
        boolean success = false;
        if (config.getHttpsPort() != null && config.getHttpsHost() != null) {
            String sslClientConfPath = clientConfigFolder + "/ssl-client.conf";
            config.setString(SSLFactory.SSL_HOSTNAME_VERIFIER_KEY, "ALLOW_ALL");
            config.setString(SSLFactory.SSL_CLIENT_CONF_KEY, sslClientConfPath);
            config.setBoolean(SSLFactory.SSL_REQUIRE_CLIENT_CERT_KEY, false);

            URLConnectionFactory connectionFactory = URLConnectionFactory
                .newDefaultURLConnectionFactory(config);

            URL url;
            String[] hosts = config.getHttpsHost().split(",");
            for (String host : hosts) {
                try {
                    url = new URL("https://" + host.trim() + ":" + config.getHttpsPort()
                        + "/has/v1?type=" + type + "&authToken=" + tokenString);
                } catch (MalformedURLException e) {
                    LOG.warn("Failed to get url. " + e.toString());
                    continue;
                }
                HttpURLConnection conn;
                try {
                    conn = (HttpURLConnection) connectionFactory.openConnection(url);
                } catch (IOException e) {
                    LOG.warn("Failed to open connection. " + e.toString());
                    continue;
                }

                conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                try {
                    conn.setRequestMethod("PUT");
                } catch (ProtocolException e) {
                    LOG.warn("Failed to set request method. " + e.toString());
                    continue;
                }
                conn.setDoOutput(true);
                conn.setDoInput(true);
                try {
                    conn.connect();

                    responseStatus = conn.getResponseCode();
                    switch (responseStatus) {
                        case 200:
                        case 201:
                            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                            StringBuilder sb = new StringBuilder();
                            String line;
                            while ((line = br.readLine()) != null) {
                                sb.append(line + "\n");
                            }
                            br.close();

                            json = new JSONObject(sb.toString());
                    }

                } catch (IOException | JSONException e) {
                    LOG.warn("ERROR! " + e.toString());
                    continue;
                }

                if (responseStatus == 200 || responseStatus == 201) {
                    success = true;
                    break;
                }
            }
            if (!success) {
                throw new HasException("Failed: HTTP error code : "
                    + responseStatus);
            }
        } else {
            throw new HasException("Please set https host and port.");
        }

        try {
            return handleResponse(json, (String) authToken.getAttributes().get("passPhrase"));
        } catch (HasException e) {
            LOG.debug("Failed to handle response when requesting tgt ticket in client."
                + e.getMessage());
            throw new HasException(e.getMessage());
        }
    }

    private File loadSslClientConf(HasConfig config, String sslClientConfPath) throws HasException {
        File sslClientConf = new File(sslClientConfPath);
        if (!sslClientConf.exists()) {
            String httpHost = config.getHttpHost();
            String httpPort = config.getHttpPort();
            if (httpHost == null) {
                // Can't find the http host in config, the https host will be used.
                httpHost = config.getHttpsHost();
            }
            if (httpPort == null) {
                // Can't find the http port in config, the default http port will be used.
                httpPort = HAS_HTTP_PORT_DEFAULT;
            }
            X509Certificate certificate = getCertificate(httpHost, httpPort);
            if (verifyCertificate(certificate)) {
                String password = createTrustStore(config.getHttpsHost(), certificate);
                createClientSSLConfig(password);
            } else {
                throw new HasException("The certificate from HAS server is invalid.");
            }
        }
        return sslClientConf;
    }

    public KrbMessage getKrbMessage(JSONObject json) throws HasException {

        try {
            boolean success = json.getBoolean("success");
            if (!success) {
                LOG.debug(json.getString("KrbMessage"));
                throw new HasException(json.getString("krbMessage"));
            }
        } catch (JSONException e) {
            LOG.debug("Failed to get message. " + e.getMessage());
            throw new HasException("Failed to get message." + e.getMessage());
        }

        String typeString;
        try {
            typeString = json.getString("type");
        } catch (JSONException e) {
            LOG.debug("Failed to get message." + e.getMessage());
            throw new HasException("Failed to get message." + e.getMessage());
        }

        if (typeString != null && typeString.equals(type)) {
            String krbMessageString;
            try {
                krbMessageString = json.getString("krbMessage");
            } catch (JSONException e) {
                LOG.debug("Failed to get the krbMessage. " + e.getMessage());
                throw new HasException("Failed to get the krbMessage. " + e.getMessage());
            }
            Base64 base64 = new Base64(0);
            byte[] krbMessage = base64.decode(krbMessageString);
            ByteBuffer byteBuffer = ByteBuffer.wrap(krbMessage);
            KrbMessage kdcRep;
            try {
                kdcRep = KrbCodec.decodeMessage(byteBuffer);
            } catch (IOException e) {
                LOG.debug("Krb decoding message failed. " + e.getMessage());
                throw new HasException("Krb decoding message failed. " + e.getMessage());
            }
            return kdcRep;
        } else {
            throw new HasException("Can't get the right message from server.");
        }
    }

    public TgtTicket handleResponse(JSONObject json, String passPhrase)
        throws HasException {
        KrbMessage kdcRep = getKrbMessage(json);

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            return processResponse((KdcRep) kdcRep, passPhrase);
        } else if (messageType == KrbMessageType.KRB_ERROR) {
            KrbError error = (KrbError) kdcRep;
            LOG.error("HAS server response with message: "
                + error.getErrorCode().getMessage());

            throw new HasException(error.getEtext());
        }
        return null;
    }

    public TgtTicket processResponse(KdcRep kdcRep, String passPhrase)
        throws HasException {

        PrincipalName clientPrincipal = kdcRep.getCname();
        String clientRealm = kdcRep.getCrealm();
        clientPrincipal.setRealm(clientRealm);

        // Get the client to decrypt the EncryptedData
        EncryptionKey clientKey = null;
        try {
            clientKey = HasUtil.getClientKey(clientPrincipal.getName(),
                passPhrase,
                kdcRep.getEncryptedEncPart().getEType());
        } catch (KrbException e) {
            throw new HasException("Could not generate key. " + e.getMessage());
        }

        byte[] decryptedData = decryptWithClientKey(kdcRep.getEncryptedEncPart(),
            KeyUsage.AS_REP_ENCPART, clientKey);
        if ((decryptedData[0] & 0x1f) == 26) {
            decryptedData[0] = (byte) (decryptedData[0] - 1);
        }
        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        try {
            encKdcRepPart.decode(decryptedData);
        } catch (IOException e) {
            throw new HasException("Failed to decode EncAsRepPart. " + e.getMessage());
        }
        kdcRep.setEncPart(encKdcRepPart);

        TgtTicket tgtTicket = getTicket(kdcRep);
        LOG.debug("Ticket expire time: " + tgtTicket.getEncKdcRepPart().getEndTime());

        storeTgtTicket(tgtTicket);

        return tgtTicket;

    }

    private void storeTgtTicket(TgtTicket tgtTicket) throws HasException {
        String ccacheName = getCcacheName();
        File ccacheFile = new File(ccacheName);
        LOG.debug("Storing the tgt to the credential cache file.");
        if (!ccacheFile.exists()) {
            createCacheFile(ccacheFile);
        }
        if (ccacheFile.exists() && ccacheFile.canWrite()) {
            CredentialCache cCache = new CredentialCache(tgtTicket);
            try {
                cCache.store(ccacheFile);
            } catch (IOException e) {
                throw new HasException("Failed to store tgt. " + e.getMessage());
            }
        } else {
            throw new IllegalArgumentException("Invalid ccache file, "
                    + "not exist or writable: " + ccacheFile.getAbsolutePath());
        }
    }

    /**
     * Create the specified credential cache file.
     */
    private void createCacheFile(File ccacheFile) throws HasException {
        try {
            if (!ccacheFile.createNewFile()) {
                throw new HasException("Failed to create ccache file "
                        + ccacheFile.getAbsolutePath());
            }
            // sets read-write permissions to owner only
            ccacheFile.setReadable(true, true);
            if (!ccacheFile.setWritable(true, true)) {
                throw new HasException("Cache file is not readable.");
            }
        } catch (IOException e) {
            throw new HasException("Failed to create ccache file "
                    + ccacheFile.getAbsolutePath() + ". " + e.getMessage());
        }
    }

    /**
     * Get credential cache file name.
     */
    private String getCcacheName() {
        final String ccacheNameEnv = System.getenv("KRB5CCNAME");
        String ccacheName;
        if (ccacheNameEnv != null) {
            ccacheName = ccacheNameEnv;
        } else {
            StringBuilder uid = new StringBuilder();
            try {
                //Get UID through "id -u" command
                String command = "id -u";
                Process child = Runtime.getRuntime().exec(command);
                InputStream in = child.getInputStream();
                int c;
                while ((c = in.read()) != -1) {
                    uid.append((char) c);
                }
                in.close();
            } catch (IOException e) {
                System.err.println("Failed to get UID.");
                System.exit(1);
            }
            ccacheName = "krb5cc_" + uid.toString().trim();
            ccacheName = SysUtil.getTempDir().toString() + "/" + ccacheName;
        }

        return ccacheName;
    }

    protected byte[] decryptWithClientKey(EncryptedData data,
                                          KeyUsage usage,
                                          EncryptionKey clientKey) throws HasException {
        if (clientKey == null) {
            throw new HasException("Client key isn't available");
        }
        try {
            return EncryptionHandler.decrypt(data, clientKey, usage);
        } catch (KrbException e) {
            throw new HasException("Errors occurred when decrypting the data." + e.getMessage());
        }
    }

    /**
     * Get the tgt ticket from KdcRep
     *
     * @param kdcRep
     */
    public TgtTicket getTicket(KdcRep kdcRep) {
        TgtTicket tgtTicket = new TgtTicket(kdcRep.getTicket(),
            (EncAsRepPart) kdcRep.getEncPart(), kdcRep.getCname());
        return tgtTicket;
    }

    /**
     * Get certificate from HAS server.
     *
     */
    private X509Certificate getCertificate(String host, String port) throws HasException {
        X509Certificate certificate;

        HttpURLConnection httpConn = null;

        URL url;
        try {
            url = new URL("http://" + host + ":" + port + "/has/v1/conf/getcert");
        } catch (MalformedURLException e) {
            throw new HasException("Failed to create a URL object." + e.getMessage());
        }
        try {
            httpConn = (HttpURLConnection) url.openConnection();
        } catch (IOException e) {
            e.printStackTrace();
        }
        httpConn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            LOG.error("Failed to add principal. " + e);
            throw new HasException("Failed to set the method for URL request. " + e.getMessage());
        }

        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                throw new HasException(HasClientUtil.getResponse(httpConn));
            }
            try {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                InputStream in = HasClientUtil.getInputStream(httpConn);
                certificate = (X509Certificate) factory.generateCertificate(in);
            } catch (CertificateException e) {
                throw new HasException("Failed to get certificate from HAS server. "
                    + e.getMessage());
            }

        } catch (IOException e) {
            throw new HasException("IO error occurred. " + e.getMessage());
        }

        return certificate;
    }

    /**
     * Verify certificate.
     */
    private boolean verifyCertificate(X509Certificate certificate) throws HasException {
        // Check if certificate is expired
        try {
            Date date = new Date();
            certificate.checkValidity(date);
        } catch (GeneralSecurityException e) {
            return false;
        }

        // Get certificate from ca root
        X509Certificate caRoot;
        try {
            //Get the ca root path from env, client should export it.
            String caRootPath = System.getenv("CA_ROOT");
            if (caRootPath == null) {
                caRootPath = CA_ROOT_DEFAULT;
            }
            File caRootFile;
            if (caRootPath != null) {
                caRootFile = new File(caRootPath);
                if (!caRootFile.exists()) {
                    LOG.debug("CA_ROOT: " + caRootPath + " not exist.");
                    throw new HasException("CA_ROOT: " + caRootPath + " not exist.");
                }
            } else {
                throw new HasException("Please set the CA_ROOT.");
            }

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (FileInputStream in = new FileInputStream(caRootFile)) {
                caRoot = (X509Certificate) factory.generateCertificate(in);
            }
        } catch (CertificateException | IOException e) {
            throw new HasException("Failed to get certificate from ca root file. "
                + e.getMessage());
        }

        // Verify certificate with root certificate
        try {
            PublicKey publicKey = caRoot.getPublicKey();
            certificate.verify(publicKey);
        } catch (GeneralSecurityException e) {
            return false;
        }

        return true;
    }

    /**
     * Create and save truststore file based on certificate.
     *
     */
    private String createTrustStore(String host, X509Certificate certificate) throws HasException {
        KeyStore trustStore;

        // Create password
        RandomStringGenerator generator = new RandomStringGenerator.Builder()
            .withinRange('a', 'z')
            .filteredBy(CharacterPredicates.LETTERS, CharacterPredicates.DIGITS)
            .build();
        String password = generator.generate(15);

        File trustStoreFile = new File(clientConfigFolder + "/truststore.jks");
        try {
            trustStore = KeyStore.getInstance("jks");
            trustStore.load(null, null);
            trustStore.setCertificateEntry(host, certificate);
            FileOutputStream out = new FileOutputStream(trustStoreFile);
            trustStore.store(out, password.toCharArray());
            out.close();
        } catch (IOException | GeneralSecurityException e) {
            throw new HasException("Failed to create and save truststore file. "
                + e.getMessage());
        }
        return password;
    }

    /**
     * Create ssl configuration file for client.
     *
     */
    private void createClientSSLConfig(String password) throws HasException {
        String resourcePath = "/ssl-client.conf.template";
        InputStream templateResource = getClass().getResourceAsStream(resourcePath);
        try {
            String content = IOUtil.readInput(templateResource);
            content = content.replaceAll("_location_", clientConfigFolder.getAbsolutePath()
                + "/truststore.jks");
            content = content.replaceAll("_password_", password);

            IOUtil.writeFile(content, new File(clientConfigFolder + "/ssl-client.conf"));
        } catch (IOException e) {
            throw new HasException("Failed to create client ssl configuration file. "
                + e.getMessage());
        }
    }
}
