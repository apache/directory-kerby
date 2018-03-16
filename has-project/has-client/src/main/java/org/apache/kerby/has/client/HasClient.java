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

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
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
            LOG.error("Plugin login failed: " + e.getMessage());
            throw new HasException(
                "Plugin login failed: " + e.getMessage());
        }
        type = plugin.getLoginType();

        LOG.debug("The plugin type is: " + type);

        return requestTgt(authToken, type, config);
    }

    private HasClientPlugin getClientTokenPlugin(HasConfig config) throws HasException {
        String pluginName = config.getPluginName();
        LOG.debug("The plugin name getting from config is: " + pluginName);
        HasClientPlugin clientPlugin;
        if (pluginName != null) {
            clientPlugin = HasClientPluginRegistry.createPlugin(pluginName);
        } else {
            throw new HasException("Please set the plugin name in has client conf");
        }
        LOG.debug("The plugin class is: " + clientPlugin);

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
            LOG.debug("Failed to decode the auth token.");
            throw new HasException("Failed to decode the auth token." + e.getMessage());
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
                throw new HasException("Failed : HTTP error code : "
                    + responseStatus);
            }
        } else {
            WebResource webResource;
            Client client = Client.create();
            String[] hosts = config.getHttpHost().split(",");
            for (String host : hosts) {
                webResource = client
                    .resource("http://" + host.trim() + ":" + config.getHttpPort()
                        + "/has/v1?type=" + type + "&authToken="
                        + tokenString);
                try {
                    ClientResponse response = webResource.accept("application/json")
                        .put(ClientResponse.class);

                    if (response.getStatus() != 200) {
                        LOG.warn("WARN! " + response.getEntity(String.class));
                        responseStatus = response.getStatus();
                        continue;
                    }
                    json = response.getEntity(JSONObject.class);
                    success = true;
                    break;
                } catch (ClientHandlerException e) {
                    LOG.warn("WARN! " + e.toString());
                    continue;
                }
            }
            if (!success) {
                throw new HasException("Failed : HTTP error code : "
                    + responseStatus);
            }
        }

        LOG.debug("Return from Server .... \n");

        try {
            return handleResponse(json, (String) authToken.getAttributes().get("passPhrase"));
        } catch (HasException e) {
            LOG.debug("Failed to handle response when requesting tgt ticket in client."
                + e.getMessage());
            throw new HasException(e);
        }
    }

    private File loadSslClientConf(HasConfig config, String sslClientConfPath) throws HasException {
        File sslClientConf = new File(sslClientConfPath);
        if (!sslClientConf.exists()) {
            String httpHost = config.getHttpHost();
            String httpPort = config.getHttpPort();
            if (httpHost == null) {
                LOG.warn("Can't find the http host in config, the https host will be used.");
                httpHost = config.getHttpsHost();
            }
            if (httpPort == null) {
                LOG.warn("Can't find the http port in config, the default http port will be used.");
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

        LOG.debug("Starting to get the message from has server.");

        try {
            boolean success = json.getBoolean("success");
            if (!success) {
                throw new HasException("Failed: " + json.getString("krbMessage"));
            }
        } catch (JSONException e) {
            LOG.debug("Failed to get message." + e);
            throw new HasException("Failed to get message." + e);
        }

        String typeString;
        try {
            typeString = json.getString("type");
        } catch (JSONException e) {
            LOG.debug("Failed to get message." + e);
            throw new HasException("Failed to get message." + e);
        }

        if (typeString != null && typeString.equals(type)) {
            LOG.debug("The message type is " + type);
            String krbMessageString = null;
            try {
                krbMessageString = json.getString("krbMessage");
            } catch (JSONException e) {
                LOG.debug("Failed to get the krbMessage. " + e);
            }
            Base64 base64 = new Base64(0);
            byte[] krbMessage = base64.decode(krbMessageString);
            ByteBuffer byteBuffer = ByteBuffer.wrap(krbMessage);
            KrbMessage kdcRep;
            try {
                kdcRep = KrbCodec.decodeMessage(byteBuffer);
            } catch (IOException e) {
                throw new HasException("Krb decoding message failed", e);
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
            LOG.error("KDC server response with message: "
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
            throw new HasException("Failed to decode EncAsRepPart", e);
        }
        kdcRep.setEncPart(encKdcRepPart);

        TgtTicket tgtTicket = getTicket(kdcRep);
        LOG.debug("Ticket expire time: " + tgtTicket.getEncKdcRepPart().getEndTime());
        return tgtTicket;

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
        Client client = Client.create();
        WebResource webResource = client.resource("http://" + host + ":" + port + "/has/v1/getcert");
        ClientResponse response = webResource.get(ClientResponse.class);
        if (response.getStatus() != 200) {
            throw new HasException(response.getEntity(String.class));
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            InputStream in = response.getEntityInputStream();
            certificate = (X509Certificate) factory.generateCertificate(in);
        } catch (CertificateException e) {
            throw new HasException("Failed to get certificate from HAS server", e);
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
            throw new HasException("Failed to get certificate from ca root file", e);
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
            throw new HasException("Failed to create and save truststore file", e);
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
            throw new HasException("Failed to create client ssl configuration file", e);
        }
    }
}
