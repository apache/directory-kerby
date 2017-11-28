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

import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class HasAuthAdminClient extends HasAdminClient {
    public static final Logger LOG = LoggerFactory.getLogger(HasAuthAdminClient.class);

    /**
     * Create an instance of the HasAuthAdminClient.
     *
     * @param hasConfig the has config
     */
    public HasAuthAdminClient(HasConfig hasConfig) {
        super(hasConfig);
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
    @Override
    protected HttpURLConnection createConnection(URL url, String method) {
        HttpURLConnection conn = null;
        if ((getHasConfig().getHttpsPort() != null) && (getHasConfig().getHttpsHost() != null)) {
            try {
                conn = super.getHttpsConnection(url, true);
            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }
        if (method.equals("POST") || method.equals("PUT")) {
            conn.setDoOutput(true);
        }
        return conn;
    }

    private String getBaseURL() {
        String url = null;
        if ((getHasConfig().getHttpsPort() != null) && (getHasConfig().getHttpsHost() != null)) {
            url = "https://" + getHasConfig().getHttpsHost() + ":" + getHasConfig().getHttpsPort()
                + "/has/v1/admin/";
        }
        if (url == null) {
            throw new RuntimeException("Please set the https address and port.");
        }
        return url;
    }

    public void addPrincipal(String principal) throws HasException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getBaseURL() + "addprincipal?principal=" + principal);
        } catch (MalformedURLException e) {
            throw new HasException(e);
        }

        httpConn = createConnection(url, "POST");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("POST");
        } catch (ProtocolException e) {
            LOG.error("Fail to add principal. " + e);
            throw new HasException(e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                System.out.println(getResponse(httpConn));
            } else {
                throw new HasException("Fail to add principal \"" + principal + "\".");
            }
        } catch (Exception e) {
            LOG.error("Fail to add principal. " + e);
            throw new HasException(e);
        }
    }

    public void setEnableOfConf(String isEnable) throws HasException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getBaseURL() + "setconf?isEnable=" + isEnable);
        } catch (MalformedURLException e) {
            throw new HasException(e);
        }

        httpConn = createConnection(url, "PUT");

        httpConn.setRequestProperty("Content-Type",
                "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("PUT");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();
            InputStream inputStream = httpConn.getResponseCode() == 200
                    ? httpConn.getInputStream() : httpConn.getErrorStream();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(inputStream));
            String s;
            StringBuilder result = new StringBuilder();
            while ((s = reader.readLine()) != null) {
                result.append(s);
            }
            if (httpConn.getResponseCode() == 200) {
                System.out.println(result);
            } else {
                System.err.println(result);
            }
        } catch (Exception e) {
            LOG.error("Fail to connect to server. " + e);
            throw new HasException(e);
        }
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
            System.err.println(e.getMessage());
        }
        return principalLists;
    }

    @Override
    public void requestCreatePrincipals(String hostRoles) throws HasException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getBaseURL() + "createprincipals");
        } catch (MalformedURLException e) {
            throw new HasException(e);
        }

        httpConn = createConnection(url, "POST");

        httpConn.setRequestProperty("Content-Type",
                "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("PUT");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        httpConn.setDoOutput(true);
        httpConn.setDoInput(true);
        try {
            httpConn.connect();
            OutputStream out = httpConn.getOutputStream();
            out.write(hostRoles.toString().getBytes());
            out.flush();
            out.close();
            if (httpConn.getResponseCode() == 200) {
                System.out.println(getResponse(httpConn));
            } else {
                throw new HasException("Connection deined.");
            }
        } catch (Exception e) {
            throw new HasException(e);
        }
    }

    @Override
    public File getKeytabByHostAndRole(String host, String role) throws HasException {
        String keytabName = host + ".zip";
        HttpURLConnection httpConn;
        String request = getBaseURL() + "exportkeytabs?host=" + host;
        if (!role.equals("")) {
            request = request + "&role=" + role;
            keytabName = role + "-" + host + ".keytab";
        }

        URL url;
        try {
            url = new URL(request);
        } catch (MalformedURLException e) {
            throw new HasException(e);
        }

        httpConn = createConnection(url, "GET");

        httpConn.setRequestProperty("Content-Type",
            "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        httpConn.setDoOutput(true);
        httpConn.setDoInput(true);
        try {
            httpConn.connect();

            if (httpConn.getResponseCode() != 200) {
                System.err.println("Error : connection denied.");
                return null;
            }
            FileOutputStream fos = new FileOutputStream(new File(keytabName));
            InputStream in = httpConn.getInputStream();
            byte[] buffer = new byte[4 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            in.close();
        } catch (IOException e) {
            throw new HasException(e);
        }
        System.out.println("Accept keytab file \"" + keytabName + "\" from server.");

        return new File(keytabName);
    }

    @Override
    public void exportKeytab(File keytab, String principal) throws HasException {
        URL url = null;
        try {
            url = new URL(getBaseURL() + "exportkeytab?principal=" + principal);
        } catch (MalformedURLException e) {
            LOG.error("Fail to get url. " + e);
            throw new HasException("Fail to get url.", e);
        }

        HttpURLConnection httpConn = createConnection(url, "GET");
        httpConn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        httpConn.setDoOutput(true);
        httpConn.setDoInput(true);
        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                System.err.println("Error: connection denied.");
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
            throw new HasException(e);
        }
        System.out.println("Receive keytab file \"" + keytab.getName() + "\" from server successfully.");
    }

    @Override
    public void exportKeytab(File keytabFile, List<String> principals) throws HasException {
        HttpURLConnection httpConn;
        for (String principal: principals) {
            String request = getBaseURL() + "exportkeytab?principal=" + principal;
            URL url;
            try {
                url = new URL(request);
            } catch (MalformedURLException e) {
                throw new HasException(e);
            }
            httpConn = createConnection(url, "GET");
            httpConn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            try {
                httpConn.setRequestMethod("GET");
            } catch (ProtocolException e) {
                throw new HasException(e);
            }
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            try {
                httpConn.connect();
                if (httpConn.getResponseCode() != 200) {
                    System.err.println("Error: connection denied.");
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
                throw new HasException(e);
            }
        }
        System.out.println("Accept keytab file \"" + keytabFile.getName() + "\" from server.");
    }

    @Override
    public void addPrincipal(String principal, String password) throws HasException {
        HttpURLConnection httpConn;

        URL url = null;
        try {
            url = new URL(getBaseURL() + "addprincipal?principal=" + principal
                            + "&password=" + password);
        } catch (MalformedURLException e) {
            throw new HasException("Fail to get url.", e);
        }

        httpConn = createConnection(url, "POST");

        httpConn.setRequestProperty("Content-Type",
                "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("POST");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                System.out.println(getResponse(httpConn));
            } else {
                throw new HasException("Fail to add principal \"" + principal + "\".");
            }
        } catch (Exception e) {
            throw new HasException(e);
        }
    }

    @Override
    public void deletePrincipal(String principal) throws HasException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getBaseURL() + "deleteprincipal?principal=" + principal);
        } catch (MalformedURLException e) {
            throw new HasException(e);
        }

        httpConn = createConnection(url, "DELETE");

        httpConn.setRequestProperty("Content-Type",
                "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("DELETE");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                System.out.println(getResponse(httpConn));
            } else {
                throw new HasException("Connection deined.");
            }
        } catch (Exception e) {
            throw new HasException(e);
        }
    }

    @Override
    public void renamePrincipal(String oldPrincipal, String newPrincipal) throws HasException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getBaseURL() + "renameprincipal?oldprincipal=" + oldPrincipal
                            + "&newprincipal=" + newPrincipal);
        } catch (MalformedURLException e) {
            throw new HasException(e);
        }

        httpConn = createConnection(url, "POST");

        httpConn.setRequestProperty("Content-Type",
                "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("POST");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                System.out.println(getResponse(httpConn));
            } else {
                throw new HasException("Connection to renameprincipal deined.");
            }
        } catch (Exception e) {
            throw new HasException(e);
        }
    }

    @Override
    public List<String> getPrincipals() throws HasException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getBaseURL() + "getprincipals");
        } catch (MalformedURLException e) {
            System.err.println(e.getMessage());
            throw new HasException(e);
        }

        httpConn = createConnection(url, "GET");

        httpConn.setRequestProperty("Content-Type",
                "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            throw new HasException(e);
        }
        String response;
        try {
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                response = getResponse(httpConn);
            } else {
                throw new HasException("Connection to getprincipals deined.");
            }
        } catch (Exception e) {
            LOG.error("Fail to get principals." + e);
            throw new HasException("Fail to get principals.", e);
        }
        return getPrincsList(response);
    }

    @Override
    public List<String> getPrincipals(String exp) throws HasException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getBaseURL() + "getprincipals?exp=" + exp);
        } catch (MalformedURLException e) {
            throw new HasException(e);
        }

        httpConn = createConnection(url, "GET");

        httpConn.setRequestProperty("Content-Type",
                "application/json; charset=UTF-8");
        try {
            httpConn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            LOG.error("Fail to get the principals with expression. " + e);
            throw new HasException("Fail to get the principals with expression.", e);
        }
        String response;
        try {
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                response = getResponse(httpConn);
            } else {
                throw new HasException("Connection to getprincipals deined.");
            }
        } catch (Exception e) {
            throw new HasException(e);
        }
        return getPrincsList(response);
    }

    private String getResponse(HttpURLConnection httpConn) throws Exception {
        StringBuilder data = new StringBuilder();
        BufferedReader br = new BufferedReader(new InputStreamReader(httpConn.getInputStream()));
        String s;
        while ((s = br.readLine()) != null) {
            data.append(s);
        }
        return new JSONObject(data.toString()).getString("msg");
    }
}
