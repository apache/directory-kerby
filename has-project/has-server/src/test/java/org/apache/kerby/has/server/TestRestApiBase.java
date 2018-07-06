/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.has.server;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.client.urlconnection.HTTPSProperties;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import org.apache.hadoop.fs.FileUtil;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasConfigKey;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.spnego.AuthenticationException;
import org.apache.kerby.has.common.util.URLConnectionFactory;
import org.apache.kerby.has.server.web.WebConfigKey;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.hadoop.http.HttpConfig;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.glassfish.jersey.SslConfigurator;
import org.junit.After;
import org.junit.Before;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.ws.rs.core.MultivaluedMap;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import static org.junit.Assert.assertEquals;

public class TestRestApiBase {
    private static String address;
    protected static File testDir = new File(System.getProperty("test.dir", "target"));
    private static File testClassDir = new File(testDir, "test-classes");
    private static File confDir = new File(testClassDir, "conf");
    private static File workDir = new File(testDir, "work-dir");
    private static HasServer server = null;
    private static final String KEY_STORE_DIR = TestUtil.getTempPath("keystore");
    private static File keyStoreDir = new File(KEY_STORE_DIR);
    private static HasConfig httpsConf;

    @Before
    public void startHasServer() throws Exception {
        // Create test keystoreDir and workDir.
        if (!keyStoreDir.exists() && !keyStoreDir.mkdirs()) {
                System.err.println("Failed to create keystore-dir.");
                System.exit(3);
        }

        if (!workDir.exists() && !workDir.mkdirs()) {
                System.err.println("Failed to create work-dir.");
                System.exit(3);
        }

        // Configure test HAS server.
        httpsConf = new HasConfig();
        String sslConfDir = TestUtil.getClasspathDir(TestRestApiBase.class);
        TestUtil.setupSSLConfig(KEY_STORE_DIR, sslConfDir, httpsConf, false);
        httpsConf.setString(WebConfigKey.HAS_HTTP_POLICY_KEY, HttpConfig.Policy.HTTPS_ONLY.name());
        httpsConf.setString(HasConfigKey.FILTER_AUTH_TYPE, "simple");

        // Start test HAS server.
        int httpsPort = 10000 + (int) (System.currentTimeMillis() % 10000); // Generate test port randomly
        String host = "localhost";
        address = host + ":" + httpsPort;
        httpsConf.setString(WebConfigKey.HAS_HTTPS_ADDRESS_KEY, address);

        server = new HasServer(confDir);
        server.setWebServer(new WebServer(httpsConf));
        server.setWorkDir(workDir);
        try {
            server.startWebServer();
        } catch (HasException e) {
            System.err.println("Errors occurred when start HAS server: " + e.toString());
            System.exit(6);
        }
    }

    @After
    public void stopHasServer() {
        server.stopWebServer();
        if (server.getKdcServer() != null) {
            server.stopKdcServer();
        }
        if (keyStoreDir.exists()) {
            FileUtil.fullyDelete(keyStoreDir);
        }
        if (workDir.exists()) {
            FileUtil.fullyDelete(workDir);
        }
    }

    private void startKdc() {
        configKDCBackend();
        WebResource webResource = getWebResource("init/kdcstart");
        ClientResponse response = webResource.put(ClientResponse.class);
        if (response.getStatus() != 200) {
            System.err.println("Errors occurred when start HAS KDC server: "
                + response.getEntity(String.class));
            System.exit(6);
        }
    }

    protected WebResource getWebResource(String restName) {
        String apiUrl = "https://" + address + "/has/v1/" + restName;
        HasConfig clientConf = new HasConfig();
        try {
            clientConf.addIniConfig(new File(httpsConf.getString(SSLFactory.SSL_CLIENT_CONF_KEY)));
        } catch (IOException e) {
            e.printStackTrace();
        }
        SslConfigurator sslConfigurator = SslConfigurator.newInstance()
            .trustStoreFile(clientConf.getString("ssl.client.truststore.location"))
            .trustStorePassword(clientConf.getString("ssl.client.truststore.password"));
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
        Client client = Client.create(clientConfig);
        return client.resource(apiUrl);
    }

    protected void configKDCBackend() {
      WebResource webResource = getWebResource("conf/configbackend");
      MultivaluedMap<String, String> params = new MultivaluedMapImpl();
      params.add("backendType", "json");
      String backend = null;
      try {
        backend = new File(testDir, "json-backend").getCanonicalPath();
      } catch (IOException e) {
        e.printStackTrace();
      }
      params.add("dir", backend);
      ClientResponse response = webResource.queryParams(params).put(ClientResponse.class);
      if (response.getStatus() != 200) {
        System.err.println("Errors occurred when config HAS KDC backend: "
            + response.getEntity(String.class));
        System.exit(7);
      }
    }

    protected void getKrb5Conf() {
        WebResource webResource = getWebResource("conf/getkrb5conf");
        ClientResponse response = webResource.get(ClientResponse.class);
        assertEquals(200, response.getStatus());
    }

    protected void getHasClientConf() {
        WebResource webResource = getWebResource("conf/gethasclientconf");
        ClientResponse response = webResource.get(ClientResponse.class);
        assertEquals(200, response.getStatus());
        File hasConf = new File(confDir, "has-client.conf");
        if (hasConf.exists() && !hasConf.delete()) {
                System.err.println("Failed to delete has-client.conf.");
        }
    }

    protected void kdcStart() {
        WebResource webResource = getWebResource("init/kdcstart");
        String response = webResource.put(String.class);
        assertEquals("Succeed in starting KDC server.", response);
    }

    protected void kdcInit() {
        startKdc();
        WebResource webResource = getWebResource("init/kdcinit");
        ClientResponse response = webResource.get(ClientResponse.class);
        assertEquals(200, response.getStatus());
    }

    protected void addPrincipalsByRole() {
        String webServerUrl = "https://" + address + "/has/v1/";
        startKdc();

        // Create test host roles json object.
        JSONObject hostRoles = new JSONObject();
        try {
            JSONObject host1 = new JSONObject();
            host1.put("name", "host1");
            host1.put("hostRoles", "HDFS,YARN");
            JSONObject host2 = new JSONObject();
            host2.put("name", "host2");
            host2.put("hostRoles", "ZOOKEEPER,HBASE");
            JSONArray hosts = new JSONArray();
            hosts.put(host1);
            hosts.put(host2);
            hostRoles.put("HOSTS", hosts);
        } catch (JSONException e) {
            System.err.println("Failed to create test host roles json object. " + e.toString());
            System.exit(6);
        }

        try {
            URL url = null;
            try {
                url = new URL(webServerUrl + "hadmin/addprincipalsbyrole");
            } catch (MalformedURLException e) {
                e.printStackTrace();
            }

            URLConnectionFactory connectionFactory = URLConnectionFactory.newDefaultURLConnectionFactory(httpsConf);
            HttpURLConnection httpConn = (HttpURLConnection) connectionFactory.openConnection(url, false, httpsConf);
            httpConn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            httpConn.setRequestMethod("PUT");
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            OutputStream out = httpConn.getOutputStream();
            out.write(hostRoles.toString().getBytes());
            out.flush();
            out.close();

            assertEquals(200, httpConn.getResponseCode());
            BufferedReader reader = httpConn.getResponseCode()
                == HttpURLConnection.HTTP_OK ? new BufferedReader(
                new InputStreamReader(httpConn.getInputStream(),
                    "UTF-8")) : new BufferedReader(
                new InputStreamReader(httpConn.getErrorStream(),
                    "UTF-8"));

            System.out.println(reader.readLine());
        } catch (IOException | AuthenticationException e) {
            System.err.println("Failed to create principals by hostRoles. " + e.toString());
            System.exit(6);
        }
    }

    protected void exportKeytabsByRole() {
        startKdc();
        WebResource webResource = getWebResource("hadmin/exportKeytabsbyrole");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("host", "host1");
        params.add("role", "HDFS");
        ClientResponse response = webResource.queryParams(params).get(ClientResponse.class);
        assertEquals(200, response.getStatus());
    }

    protected void addPrincipal() {
        startKdc();
        WebResource webResource = getWebResource("kadmin/addprincipal");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", "admin");
        params.add("password", "123");
        String response = webResource.queryParams(params).post(String.class);
        assertEquals("Add principal successfully.", response);
    }

    protected void renamePrincipal() {
        startKdc();
        WebResource webResource = getWebResource("kadmin/renameprincipal");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("oldprincipal", "admin");
        params.add("newprincipal", "admin2");
        String response = webResource.queryParams(params).post(String.class);
        assertEquals("Rename principal successfully.", response);
    }

    protected void changePassword() {
        startKdc();
        WebResource webResource = getWebResource("kadmin/changepassword");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", "admin2");
        params.add("password", "12345");
        String response = webResource.queryParams(params).post(String.class);
        assertEquals("Change password successfully.", response);
    }

    protected void exportKeytab() {
        startKdc();
        WebResource webResource = getWebResource("kadmin/exportkeytab");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", "admin2@HADOOP.COM");
        ClientResponse response = webResource.queryParams(params).get(ClientResponse.class);
        assertEquals(200, response.getStatus());
    }

    protected void getPrincipal() {
        startKdc();
        WebResource webResource = getWebResource("kadmin/getprincipal");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", "admin2@HADOOP.COM");
        ClientResponse response = webResource.queryParams(params).post(ClientResponse.class);
        assertEquals(200, response.getStatus());
    }

    protected void listPrincipals() {
        startKdc();
        WebResource webResource = getWebResource("kadmin/listprincipals");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        ClientResponse response = webResource.queryParams(params).get(ClientResponse.class);
        assertEquals(200, response.getStatus());
    }

    protected void deletePrincipal() {
        startKdc();
        WebResource webResource = getWebResource("kadmin/deleteprincipal");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("principal", "admin2");
        String response = webResource.queryParams(params).delete(String.class);
        assertEquals("Delete principal successfully.", response);
    }
}
