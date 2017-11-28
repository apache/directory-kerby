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
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.client.urlconnection.HTTPSProperties;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import org.apache.kerby.has.common.HasAdmin;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.ssl.SSLFactory;
import org.apache.kerby.has.common.util.URLConnectionFactory;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.glassfish.jersey.SslConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.ws.rs.core.MultivaluedMap;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * A Admin client API for applications to interact with KDC
 */
public class HasAdminClient implements HasAdmin {

    public static final Logger LOG = LoggerFactory.getLogger(HasAdminClient.class);

    private HasConfig hasConfig;
    private File confDir;

    public HasAdminClient(HasConfig hasConfig) {
        this.hasConfig = hasConfig;
    }
    public HasAdminClient(HasConfig hasConfig, File confDir) {
        this.hasConfig = hasConfig;
        this.confDir = confDir;
    }

    public File getConfDir() {
        return confDir;
    }

    public HasConfig getHasConfig() {
        return hasConfig;
    }

    protected HttpURLConnection getHttpsConnection(URL url, boolean isSpnego) throws Exception {
        HasConfig conf = new HasConfig();

        conf.setString(SSLFactory.SSL_HOSTNAME_VERIFIER_KEY, "ALLOW_ALL");
        String sslClientConf = hasConfig.getSslClientConf();
        conf.setString(SSLFactory.SSL_CLIENT_CONF_KEY, sslClientConf);
        conf.setBoolean(SSLFactory.SSL_REQUIRE_CLIENT_CERT_KEY, false);

        URLConnectionFactory connectionFactory = URLConnectionFactory
                .newDefaultURLConnectionFactory(conf);
        return (HttpURLConnection) connectionFactory.openConnection(url, isSpnego, hasConfig);
    }

    private WebResource getWebResource(String restName) {
        Client client;
        String server = null;
        if ((hasConfig.getHttpsPort() != null) && (hasConfig.getHttpsHost() != null)) {
            server = "https://" + hasConfig.getHttpsHost() + ":" + hasConfig.getHttpsPort()
                    + "/has/v1/" + restName;
            LOG.info("Admin request url: " + server);
            HasConfig conf = new HasConfig();
            try {
                conf.addIniConfig(new File(hasConfig.getSslClientConf()));
            } catch (IOException e) {
                throw new RuntimeException("Errors occurred when adding ssl conf. "
                    + e.getMessage());
            }
            SslConfigurator sslConfigurator = SslConfigurator.newInstance()
                    .trustStoreFile(conf.getString("ssl.client.truststore.location"))
                    .trustStorePassword(conf.getString("ssl.client.truststore.password"));
            sslConfigurator.securityProtocol("SSL");
            SSLContext sslContext = sslConfigurator.createSSLContext();
            ClientConfig clientConfig = new DefaultClientConfig();
            clientConfig.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES,
                    new HTTPSProperties(new HostnameVerifier() {
                        @Override
                        public boolean verify(String s, SSLSession sslSession) {
                            return false;
                        }
                    }, sslContext));
            client = Client.create(clientConfig);
        } else {
            client = Client.create();
        }
        if (server == null) {
            throw new RuntimeException("Please set the https address and port.");
        }
        return client.resource(server);
    }

    /**
     * Change principals JSON string to a List.
     *
     * @param princs principals JSON string which like
     *               "["HTTP\/host1@HADOOP.COM","HTTP\/host2@HADOOP.COM"]"
     * @return principalLists.
     */
    private List<String> getPrincsList(String princs) {
        List<String> principalLists = new ArrayList<>();
        try {
            JSONArray principals = new JSONArray(princs);
            for (int i = 0; i < principals.length(); i++) {
                principalLists.add("\t" + principals.getString(i));
            }
        } catch (Exception e) {
            System.err.println("Errors occurred when getting the principals."
                + e.getMessage());
        }
        return principalLists;
    }

    public void requestCreatePrincipals(String hostRoles) throws HasException {
        WebResource webResource = getWebResource("admin/createprincipals");
        String response = webResource.entity(hostRoles.toString().getBytes()).put(String.class);
        try {
            System.out.println(new JSONObject(response).getString("msg"));
        } catch (JSONException e) {
            throw new HasException(e);
        }
    }

    @Override
    public void addPrincipal(String principal) throws HasException {
        WebResource webResource = getWebResource("admin/addprincipal");

        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", principal);
        String response = webResource.queryParams(params).post(String.class);
        try {
            System.out.println(new JSONObject(response).getString("msg"));
        } catch (JSONException e) {
            System.err.println("Errors occurred when getting the message from response."
                + e.getMessage());
        }
    }

    @Override
    public File getKeytabByHostAndRole(String host, String role) throws HasException {
        WebResource webResource = getWebResource("admin/exportkeytabs");

        String keytabName = host + ".zip";
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("host", host);
        if (!role.equals("")) {
            params.add("role", role);
            keytabName = role + "-" + host + ".keytab";
        }
        ClientResponse response = webResource.queryParams(params).get(ClientResponse.class);
        if (response.getStatus() != 200) {
            System.err.println("Error : connection denied.");
            return null;
        }
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(new File(keytabName));
        } catch (FileNotFoundException e) {
            System.err.println(e.getMessage());
        }
        InputStream in = response.getEntityInputStream();
        byte[] buffer = new byte[4 * 1024];
        int read;
        try {
            while ((read = in.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            in.close();
        } catch (IOException e) {
            System.err.println("Errors occurred when reading the buffer to write keytab file."
                + e.getMessage());
        }
        System.out.println("Accept keytab file \"" + keytabName + "\" from server.");
        return new File(keytabName);
    }

    @Override
    public void addPrincipal(String principal, String password) throws HasException {
        WebResource webResource = getWebResource("admin/addprincipal");

        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", principal);
        params.add("password", password);
        String response = webResource.queryParams(params).post(String.class);
        try {
            System.out.println(new JSONObject(response).getString("msg"));
        } catch (JSONException e) {
            System.err.println("Errors occurred when getting the message from response."
                + e.getMessage());
        }
    }

    @Override
    public void deletePrincipal(String principal) throws HasException {
        WebResource webResource = getWebResource("admin/deleteprincipal");

        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", principal);
        String response = webResource.queryParams(params).delete(String.class);
        try {
            System.out.println(new JSONObject(response).getString("msg"));
        } catch (JSONException e) {
            System.err.println("Errors occurred when getting the message from response."
                + e.getMessage());
        }
    }

    @Override
    public void renamePrincipal(String oldPrincipal, String newPrincipal) throws HasException {
        WebResource webResource = getWebResource("admin/renameprincipal");

        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("oldprincipal", oldPrincipal);
        params.add("newprincipal", newPrincipal);
        String response = webResource.queryParams(params).post(String.class);
        try {
            System.out.println(new JSONObject(response).getString("msg"));
        } catch (JSONException e) {
            System.err.println(e.getMessage());
        }
    }

    @Override
    public List<String> getPrincipals() throws HasException {
        WebResource webResource = getWebResource("admin/getprincipals");

        String response = webResource.get(String.class);
        String princs = null;
        try {
            princs = new JSONObject(response).getString("msg");
        } catch (JSONException e) {
            System.err.println("Errors occurred when getting the message from response."
                + e.getMessage());
        }
        return getPrincsList(princs);
    }

    @Override
    public List<String> getPrincipals(String exp) throws HasException {
        WebResource webResource = getWebResource("admin/getprincipals");

        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("exp", exp);
        String response = webResource.queryParams(params).get(String.class);
        return getPrincsList(response);
    }

    /**
     * Create http connection to has server.
     *
     * @param url
     * @param method
     * @return connection
     * @throws IOException
     */
    protected HttpURLConnection createConnection(URL url, String method) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        if (method.equals("POST") || method.equals("PUT")) {
            conn.setDoOutput(true);
        }
        return conn;
    }

    @Override
    public String addPrincByRole(String host, String role) throws HasException {
        //TODO
        return null;
    }

    @Override
    public String getHadminPrincipal() {
        return KrbUtil.makeKadminPrincipal(hasConfig.getRealm()).getName();
    }

    /**
     * get size of principal
     */
    @Override
    public int size() throws HasException {
        return this.getPrincipals().size();
    }

    public String getKrb5conf() {
        WebResource webResource = getWebResource("getkrb5conf");
        ClientResponse response = webResource.get(ClientResponse.class);
        if (response.getStatus() == 200) {
            return response.getEntity(String.class);
        }
        return null;
    }

    public String getHasconf() {
        WebResource webResource = getWebResource("gethasconf");
        ClientResponse response = webResource.get(ClientResponse.class);
        if (response.getStatus() == 200) {
            return response.getEntity(String.class);
        }
        return null;
    }
    public void setPlugin(String plugin) {
        WebResource webResource = getWebResource("conf/setplugin");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("plugin", plugin);
        ClientResponse response = webResource.queryParams(params).put(ClientResponse.class);
        if (response.getStatus() == 200) {
            System.out.println(response.getEntity(String.class));
        } else if (response.getStatus() == 400) {
            System.err.println(response.getEntity(String.class));
        }
    }
    public void configKdc(String port, String realm, String host) {
        WebResource webResource = getWebResource("conf/configkdc");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("port", port);
        params.add("realm", realm);
        params.add("host", host);
        ClientResponse response = webResource.queryParams(params).put(ClientResponse.class);
        if (response.getStatus() == 200) {
            System.out.println(response.getEntity(String.class));
        } else if (response.getStatus() == 400) {
            System.err.println(response.getEntity(String.class));
        }
    }
    public void configKdcBackend(String backendType, String dir, String url, String user,
                                 String password) {
        WebResource webResource = getWebResource("conf/configkdcbackend");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("backendType", backendType);
        if (backendType.equals("json")) {
            params.add("dir", dir);
        } else if (backendType.equals("mysql")) {
            params.add("url", url);
            params.add("user", user);
            params.add("password", password);
        }
        ClientResponse response = webResource.queryParams(params).put(ClientResponse.class);
        if (response.getStatus() == 200) {
            System.out.println(response.getEntity(String.class));
        } else if (response.getStatus() == 400) {
            System.err.println(response.getEntity(String.class));
        }
    }
    public void startKdc() {
        WebResource webResource = getWebResource("kdcstart");
        ClientResponse response = webResource.get(ClientResponse.class);
        try {
            JSONObject result = new JSONObject(response.getEntity(String.class));
            if (result.getString("result").equals("success")) {
                System.out.println(result.getString("msg"));
            } else {
                System.err.println(result.getString("msg"));
            }
        } catch (JSONException e) {
            System.err.println(e.getMessage());
        }
    }
    public InputStream initKdc() {
        WebResource webResource = getWebResource("kdcinit");
        ClientResponse response = webResource.get(ClientResponse.class);
        if (response.getStatus() == 200) {
            return response.getEntityInputStream();
        }
        return null;
    }
    public String getHostRoles() {
        WebResource webResource = getWebResource("hostroles");
        ClientResponse response = webResource.get(ClientResponse.class);
        if (response.getStatus() == 200) {
            return response.getEntity(String.class);
        }
        return null;
    }
    public void setEnableOfConf(String isEnable) throws HasException {
        WebResource webResource = getWebResource("admin/setconf");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("isEnable", isEnable);
        ClientResponse response = webResource.queryParams(params).put(ClientResponse.class);
        if (response.getStatus() == 200) {
            System.out.println(response.getEntity(String.class));
        } else {
            System.err.println(response.getEntity(String.class));
        }
    }

    @Override
    public void exportKeytab(File keytab, String principal) throws HasException {
        WebResource webResource = getWebResource("admin/exportkeytab");

        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", principal);
        ClientResponse response = webResource.queryParams(params).get(ClientResponse.class);
        FileOutputStream fos;
        try {
            fos = new FileOutputStream(keytab);
        } catch (FileNotFoundException e) {
            throw new HasException("The keytab file: " + keytab + "not exist. " + e);
        }
        InputStream in = response.getEntityInputStream();
        byte[] buffer = new byte[4 * 1024];
        int read;
        try {
            while ((read = in.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            in.close();
        } catch (IOException e) {
            System.err.println("Errors occurred when writing the buffer to keytab file." + e.toString());
        }
        System.out.println("Accept keytab file \"" + keytab.getName() + "\" from server successfully.");
    }

    @Override
    public void exportKeytab(File keytabFile, List<String> principals) throws HasException {
        WebResource webResource = getWebResource("admin/exportkeytab");
        for (String principal: principals) {
            MultivaluedMap<String, String> params = new MultivaluedMapImpl();
            params.add("principal", principal);
            ClientResponse response = webResource.queryParams(params).get(ClientResponse.class);
            FileOutputStream fos;
            try {
                fos = new FileOutputStream(keytabFile);
            } catch (FileNotFoundException e) {
                throw new HasException("The keytab file: " + keytabFile.getName() + "not exist. " + e);
            }
            InputStream in = response.getEntityInputStream();
            byte[] buffer = new byte[4 * 1024];
            int read;
            try {
                while ((read = in.read(buffer)) > 0) {
                    fos.write(buffer, 0, read);
                }
                fos.close();
                in.close();
            } catch (IOException e) {
                LOG.error("Errors occurred when writing the buffer to keytab file." + e.toString());
            }
        }
        System.out.println("Accept keytab file \"" + keytabFile.getName() + "\" from server successfully.");
    }
}
