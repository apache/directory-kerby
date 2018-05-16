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

import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.ssl.SSLFactory;
import org.apache.kerby.has.common.util.URLConnectionFactory;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;

public class HasClientUtil {

    public static HttpURLConnection getHttpsConnection(HasConfig hasConfig, URL url, boolean isSpnego)
            throws Exception {
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
     * @param hasConfig the HAS client config.
     * @param url    the URL to open a HTTP connection to.
     * @param method the HTTP method for the HTTP connection.
     * @param  isSpnego  true or false.
     * @return an authenticated connection to the has server.
     * @throws IOException if an IO error occurred.
     */
    public static HttpURLConnection createConnection(HasConfig hasConfig, URL url, String method, boolean isSpnego)
            throws KrbException {
        HttpURLConnection conn = null;
        if (hasConfig.getHttpsPort() != null && hasConfig.getHttpsHost() != null) {
            try {
                conn = getHttpsConnection(hasConfig, url, isSpnego);
            } catch (Exception e) {
                throw new KrbException("Error occurred when creating https connection. "
                        + e.getMessage());
            }
        }
        try {
            conn.setRequestMethod(method);
        } catch (ProtocolException e) {
            throw new KrbException("Failed to set the method for URL request.", e);
        }
        if (method.equals("POST") || method.equals("PUT")) {
            conn.setDoOutput(true);
        }
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        return conn;
    }

    public static String getBaseUrl(HasConfig hasConfig, String input) throws KrbException {
        String url = null;
        if (hasConfig.getHttpsPort() != null && hasConfig.getHttpsHost() != null) {
            url = "https://" + hasConfig.getHttpsHost() + ":" + hasConfig.getHttpsPort()
                    + "/has/v1/" + input + "/";
        }
        if (url == null) {
            throw new KrbException("Please set the https address and port.");
        }
        return url;
    }

    public static String getResponse(HttpURLConnection httpConn) throws IOException {
        StringBuilder data = new StringBuilder();

        InputStream inputStream = getInputStream(httpConn);
        BufferedReader br;
        if (inputStream != null) {
          br = new BufferedReader(new InputStreamReader(inputStream));
        } else {
            throw new IOException("Failed to get the InputStream");
        }
        String s;
        while ((s = br.readLine()) != null) {
            data.append(s);
        }
        return data.toString();
    }

    public static InputStream getInputStream(HttpURLConnection httpConn) throws IOException {
        InputStream inputStream;
        if (httpConn.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
            inputStream = httpConn.getInputStream();
        } else {
            /* Error from server */
            inputStream = httpConn.getErrorStream();
        }
        return inputStream;
    }
}
