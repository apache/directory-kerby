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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * HAS client API for applications to interact with HAS server
 */
public class HasInitClient {

    public static final Logger LOG = LoggerFactory.getLogger(HasInitClient.class);

    private HasConfig hasConfig;
    private File confDir;

    public HasInitClient(HasConfig hasConfig, File confDir) {
        this.hasConfig = hasConfig;
        this.confDir = confDir;
    }

    public File getConfDir() {
        return confDir;
    }

    private String getInitBaseURL() throws KrbException {
        return HasClientUtil.getBaseUrl(hasConfig, "init");
    }

    private String getConfigBaseURL() throws KrbException {
        return HasClientUtil.getBaseUrl(hasConfig, "conf");
    }

    public String startKdc() throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getInitBaseURL() + "kdcstart");
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "PUT", false);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                String response = HasClientUtil.getResponse(httpConn);
                LOG.info(response);
                return response;
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred. " + e.getMessage());
        }
    }

    public void initKdc(File keytab) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getInitBaseURL() + "kdcinit");
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", false);

        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
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
            throw new KrbException("IO error occurred. " + e.getMessage());
        }
    }

    public void getKrb5conf(File file) throws KrbException {

        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getConfigBaseURL() + "getkrb5conf");
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", false);

        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
            FileOutputStream fos = new FileOutputStream(file);
            InputStream in = httpConn.getInputStream();
            byte[] buffer = new byte[3 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            in.close();
        } catch (IOException e) {
            throw new KrbException("IO error occurred. " + e.getMessage());
        }
    }

    public void getHasClientConf(File file) throws KrbException {

        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getConfigBaseURL() + "gethasclientconf");
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", false);

        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
            FileOutputStream fos = new FileOutputStream(file);
            InputStream in = httpConn.getInputStream();
            byte[] buffer = new byte[3 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            in.close();
        } catch (IOException e) {
            throw new KrbException("IO error occurred. " + e.getMessage());
        }
    }

    public String setPlugin(String plugin) throws KrbException {

        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getConfigBaseURL() + "setplugin?plugin=" + plugin);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "PUT", false);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                String response = HasClientUtil.getResponse(httpConn);
                LOG.info(response);
                return response;
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred. " + e.getMessage());
        }
    }

    public String configKdc(String port, String realm, String host) throws KrbException {

        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getConfigBaseURL() + "configkdc?port=" + port + "&realm="
                    + realm + "&host=" + host);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "PUT", false);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                String response = HasClientUtil.getResponse(httpConn);
                LOG.info(response);
                return response;
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred. " + e.getMessage());
        }
    }

    public String configBackend(String backendType, String dir, String mysqlUrl, String user,
                              String password) throws KrbException {

        HttpURLConnection httpConn;

        URL url;
        if (backendType.equals("json")) {
            try {
                url = new URL(getConfigBaseURL() + "configbackend?backendType=" + backendType
                        + "&dir=" + dir);
            } catch (MalformedURLException e) {
                throw new KrbException("Failed to create a URL object.", e);
            }
        } else if (backendType.equals("mysql")) {
            try {
                url = new URL(getConfigBaseURL() + "configbackend?backendType=" + backendType
                        + "&url=" + mysqlUrl + "&user=" + user + "&password=" + password);
            } catch (MalformedURLException e) {
                throw new KrbException("Failed to create a URL object.", e);
            }
        } else {
            throw new KrbException("Unsupported backend: " + backendType);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "PUT", false);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                String response = HasClientUtil.getResponse(httpConn);
                LOG.info(response);
                return response;
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred. " + e.getMessage());
        }
    }
}
