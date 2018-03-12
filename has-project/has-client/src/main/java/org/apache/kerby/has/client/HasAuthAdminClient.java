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
package org.apache.kerby.has.client;

import org.apache.kerby.KOptions;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.ssl.SSLFactory;
import org.apache.kerby.has.common.util.URLConnectionFactory;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.Kadmin;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class HasAuthAdminClient implements Kadmin {
    public static final Logger LOG = LoggerFactory.getLogger(HasAuthAdminClient.class);

    private HasConfig hasConfig;

    /**
     * Create an instance of the HasAuthAdminClient.
     *
     * @param hasConfig the has config
     */
    public HasAuthAdminClient(HasConfig hasConfig) {
        this.hasConfig = hasConfig;
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

    /**
     * Create an authenticated connection to the Has server.
     * <p>
     * It uses Hadoop-auth client authentication which by default supports
     * Kerberos HTTP SPNEGO, Pseudo/Simple and anonymous.
     *
     * @param url    the URL to open a HTTP connection to.
     * @param method the HTTP method for the HTTP connection.
     * @return an authenticated connection to the has server.
     * @throws IOException if an IO error occurred.
     */
    protected HttpURLConnection createConnection(URL url, String method) {
        HttpURLConnection conn = null;
        if (hasConfig.getHttpsPort() != null && hasConfig.getHttpsHost() != null) {
            try {
                conn = getHttpsConnection(url, true);
            } catch (Exception e) {
                throw new RuntimeException("Error occurred when creating https connection. " + e.getMessage());
            }
        }
        if (method.equals("POST") || method.equals("PUT")) {
            conn.setDoOutput(true);
        }
        return conn;
    }

    private String getKadminBaseURL() {
        String url = null;
        if (hasConfig.getHttpsPort() != null && hasConfig.getHttpsHost() != null) {
            url = "https://" + hasConfig.getHttpsHost() + ":" + hasConfig.getHttpsPort()
                + "/has/v1/kadmin/";
        }
        if (url == null) {
            throw new RuntimeException("Please set the https address and port.");
        }
        return url;
    }

    @Override
    public void addPrincipal(String principal) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "addprincipal?principal=" + principal);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = createConnection(url, "POST");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("POST");
        } catch (ProtocolException e) {
            LOG.error("Fail to add principal. " + e);
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(getResponse(httpConn));
            } else {
                throw new KrbException(getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
    }

    @Override
    public void addPrincipal(String principal, String password) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "addprincipal?principal=" + principal
                + "&password=" + password);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = createConnection(url, "POST");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("POST");
        } catch (ProtocolException e) {
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(getResponse(httpConn));
            } else {
                throw new KrbException(getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
    }

    @Override
    public void addPrincipal(String principal, String password, KOptions kOptions) throws KrbException {

    }

    @Override
    public void deletePrincipal(String principal) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "deleteprincipal?principal=" + principal);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = createConnection(url, "DELETE");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("DELETE");
        } catch (ProtocolException e) {
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(getResponse(httpConn));
            } else {
                throw new KrbException("Connection deined.");
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
    }

    @Override
    public void modifyPrincipal(String principal, KOptions kOptions) throws KrbException {

    }

    @Override
    public void renamePrincipal(String oldPrincipal, String newPrincipal) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "renameprincipal?oldprincipal=" + oldPrincipal
                + "&newprincipal=" + newPrincipal);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = createConnection(url, "POST");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("POST");
        } catch (ProtocolException e) {
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(getResponse(httpConn));
            } else {
                throw new KrbException(getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
    }

    @Override
    public List<String> getPrincipals() throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "listprincipals");
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = createConnection(url, "GET");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        String response;
        try {
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                response = getResponse(httpConn);
            } else {
                throw new KrbException(getResponse(httpConn));
            }
        } catch (IOException e) {
            LOG.error("IO error occurred." + e.getMessage());
            throw new KrbException("IO error occurred.", e);
        }
        return getPrincsList(response);
    }

    @Override
    public List<String> getPrincipals(String exp) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "getprincipals?exp=" + exp);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object. ", e);
        }

        httpConn = createConnection(url, "GET");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            LOG.error("Failed to set the method for URL request." + e.getMessage());
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        String response;
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                response = getResponse(httpConn);
            } else {
                throw new KrbException(getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
        return getPrincsList(response);
    }

    /**
     * Change principals JSON string to a List.
     *
     * @param princs principals JSON string which like
     *               "["HTTP\/host1@HADOOP.COM","HTTP\/host2@HADOOP.COM"]"
     * @return principalLists.
     */
    private List<String> getPrincsList(String princs) throws KrbException {
        List<String> principalLists = new ArrayList<>();
        try {
            JSONArray principals = new JSONArray(princs);
            for (int i = 0; i < principals.length(); i++) {
                principalLists.add("\t" + principals.getString(i));
            }
        } catch (JSONException e) {
            throw new KrbException("JSON Exception occurred. ", e);
        }
        return principalLists;
    }

    @Override
    public void exportKeytab(File keytab, String principal) throws KrbException {
        URL url;
        try {
            url = new URL(getKadminBaseURL() + "exportkeytab?principal=" + principal);
        } catch (MalformedURLException e) {
            LOG.error("Failed to create a URL object." + e.getMessage());
            throw new KrbException("Failed to create a URL object.", e);
        }

        HttpURLConnection httpConn = createConnection(url, "GET");
        httpConn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        httpConn.setDoOutput(true);
        httpConn.setDoInput(true);
        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                throw new KrbException(getResponse(httpConn));
            }
            FileOutputStream fos = new FileOutputStream(keytab);
            InputStream in = httpConn.getInputStream();
            byte[] buffer = new byte[3 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            in.close();
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
        LOG.info("Receive keytab file \"" + keytab.getName() + "\" from server successfully.");
    }

    @Override
    public void exportKeytab(File keytabFile, List<String> principals) throws KrbException {
        HttpURLConnection httpConn;
        for (String principal : principals) {
            String request = getKadminBaseURL() + "exportkeytab?principal=" + principal;
            URL url;
            try {
                url = new URL(request);
            } catch (MalformedURLException e) {
                throw new KrbException("Failed to create a URL object.");
            }
            httpConn = createConnection(url, "GET");
            httpConn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            try {
                httpConn.setRequestMethod("GET");
            } catch (ProtocolException e) {
                throw new KrbException("Failed to set the method for URL request.", e);
            }
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            try {
                httpConn.connect();
                if (httpConn.getResponseCode() != 200) {
                    throw new KrbException(getResponse(httpConn));
                }
                FileOutputStream fos = new FileOutputStream(keytabFile);
                InputStream in = httpConn.getInputStream();
                byte[] buffer = new byte[4 * 1024];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    fos.write(buffer, 0, read);
                }
                fos.close();
                in.close();
            } catch (IOException e) {
                throw new KrbException("IO error occurred.", e);
            }
        }
        LOG.info("Accept keytab file \"" + keytabFile.getName() + "\" from server.");
    }

    @Override
    public void addPrincipal(String principal, KOptions kOptions) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public String getKadminPrincipal() {
        return null;
    }

    @Override
    public void exportKeytab(File keytabFile) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public void removeKeytabEntriesOf(File keytabFile, String principal) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public void removeKeytabEntriesOf(File keytabFile, String principal, int kvno) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public void removeOldKeytabEntriesOf(File keytabFile, String principal) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public void changePassword(String principal,
                               String newPassword) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public void updateKeys(String principal) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public void release() throws KrbException {

    }

    private String getResponse(HttpURLConnection httpConn) throws IOException {
        StringBuilder data = new StringBuilder();
        InputStream inputStream;
        if (httpConn.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
            inputStream = httpConn.getInputStream();
        } else {
            /* Error from server */
            inputStream = httpConn.getErrorStream();
        }
        BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
        String s;
        while ((s = br.readLine()) != null) {
            data.append(s);
        }
        return data.toString();
    }
}
