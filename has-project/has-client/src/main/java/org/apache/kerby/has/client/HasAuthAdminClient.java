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
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
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

    private String getKadminBaseURL() throws KrbException {
        return HasClientUtil.getBaseUrl(hasConfig, "kadmin");
    }

    private String getHadminBaseURL() throws KrbException {
        return HasClientUtil.getBaseUrl(hasConfig, "hadmin");
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

        httpConn = HasClientUtil.createConnection(hasConfig, url, "POST", true);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(HasClientUtil.getResponse(httpConn));
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
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

        httpConn = HasClientUtil.createConnection(hasConfig, url, "POST", true);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(HasClientUtil.getResponse(httpConn));
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
    }

    @Override
    public void addPrincipal(String principal, String password, KOptions kOptions) throws KrbException {
        throw new KrbException("Unsupported feature");
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

        httpConn = HasClientUtil.createConnection(hasConfig, url, "DELETE", true);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(HasClientUtil.getResponse(httpConn));
            } else {
                throw new KrbException("Connection deined.");
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
    }

    @Override
    public void modifyPrincipal(String principal, KOptions kOptions) throws KrbException {
        throw new KrbException("Unsupported feature");
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

        httpConn = HasClientUtil.createConnection(hasConfig, url, "POST", true);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(HasClientUtil.getResponse(httpConn));
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
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
        LOG.info("Remote Admin Url: " + url);

        httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", true);

        String response;
        try {
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                response = HasClientUtil.getResponse(httpConn);
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            LOG.error("IO error occurred." + e.getMessage());
            throw new KrbException("IO error occurred.", e);
        }
        return convertJsonStringToList(response);
    }

    @Override
    public List<String> getPrincipals(String exp) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "listprincipals?exp=" + exp);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object. ", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", true);

        String response;
        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                response = HasClientUtil.getResponse(httpConn);
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
        if (response == null) {
            throw new KrbException("Please initial KDC first.");
        }
        return convertJsonStringToList(response);
    }

    /**
     * Convert JSON string to a List.
     *
     * @param result principals JSON string which like
     *               "["HTTP\/host1@HADOOP.COM","HTTP\/host2@HADOOP.COM"]"
     * @return principal lists.
     */
    private List<String> convertJsonStringToList(String result) throws KrbException {
        List<String> principalLists = new ArrayList<>();
        try {
            JSONArray jsonArray = new JSONArray(result);
            for (int i = 0; i < jsonArray.length(); i++) {
                principalLists.add("\t" + jsonArray.getString(i));
            }
        } catch (JSONException e) {
            throw new KrbException("JSON Exception occurred. ", e);
        }
        return principalLists;
    }

    @Override
    public void exportKeytab(File keytabFile, String principal) throws KrbException {
        URL url;
        try {
            url = new URL(getKadminBaseURL() + "exportkeytab?principal=" + principal);
        } catch (MalformedURLException e) {
            LOG.error("Failed to create a URL object." + e.getMessage());
            throw new KrbException("Failed to create a URL object.", e);
        }

        HttpURLConnection httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", true);

        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }

            try {
                if (!keytabFile.exists() && !keytabFile.createNewFile()) {
                    throw new KrbException("Failed to create keytab file "
                            + keytabFile.getAbsolutePath());
                }
            } catch (IOException e) {
                throw new KrbException("Failed to load or create keytab "
                        + keytabFile.getAbsolutePath(), e);
            }

            FileOutputStream fos = new FileOutputStream(keytabFile);
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
        LOG.info("Receive keytab file \"" + keytabFile.getName() + "\" from server successfully.");
    }

    public void exportKeytabWithGlob(File keytabFile, String principal) throws KrbException {
        URL url;
        try {
            url = new URL(getKadminBaseURL() + "exportkeytab?principal=" + principal + "&global=true");
        } catch (MalformedURLException e) {
            LOG.error("Failed to create a URL object.", e);
            throw new KrbException("Failed to create a URL object.", e);
        }

        HttpURLConnection httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", true);
        try {
            httpConn.connect();
            if (httpConn.getResponseCode() != 200) {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }

            try {
                if (!keytabFile.exists() && !keytabFile.createNewFile()) {
                    throw new KrbException("Failed to create keytab file "
                            + keytabFile.getAbsolutePath());
                }
            } catch (IOException e) {
                throw new KrbException("Failed to load or create keytab "
                        + keytabFile.getAbsolutePath(), e);
            }

            FileOutputStream fos = new FileOutputStream(keytabFile);
            InputStream in = httpConn.getInputStream();
            byte[] buffer = new byte[3 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            in.close();
        } catch (IOException e) {
            LOG.error("IO error occurred.", e);
            throw new KrbException("IO error occurred.", e);
        }
        LOG.info("Receive keytab file " + keytabFile.getName() + " from server successfully.");
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
            httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", true);

            try {
                httpConn.connect();
                if (httpConn.getResponseCode() != 200) {
                    throw new KrbException(HasClientUtil.getResponse(httpConn));
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
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "changepassword?principal=" + principal
                    + "&password=" + newPassword);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "POST", true);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                LOG.info(HasClientUtil.getResponse(httpConn));
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            throw new KrbException("IO error occurred.", e);
        }
    }

    @Override
    public void updateKeys(String principal) throws KrbException {
        throw new KrbException("Unsupported feature");
    }

    @Override
    public void release() throws KrbException {

    }

    public List<String> addPrincipalsByRole(String hostRoles) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getHadminBaseURL() + "addprincipalsbyrole");
        } catch (MalformedURLException e) {
            throw new KrbException(e.getMessage());
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "PUT", true);

        String response;
        try {
            httpConn.connect();
            OutputStream out = httpConn.getOutputStream();
            out.write(hostRoles.toString().getBytes());
            out.flush();
            out.close();
            if (httpConn.getResponseCode() == 200) {
                response = HasClientUtil.getResponse(httpConn);
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (Exception e) {
            throw new KrbException(e.getMessage());
        }
        return convertJsonStringToList(response);
    }

    public void setEnableOfConf(String isEnable) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getHadminBaseURL() + "setconf?isEnable=" + isEnable);
        } catch (MalformedURLException e) {
            throw new KrbException(e.getMessage());
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "PUT", true);

        try {
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
            throw new KrbException(e.getMessage());
        }
    }

    public File getKeytabByHostAndRole(String host, String role) throws KrbException {
        String keytabName = host + ".zip";
        HttpURLConnection httpConn;
        String request = getHadminBaseURL() + "exportKeytabsbyrole?host=" + host;
        if (!role.equals("")) {
            request = request + "&role=" + role;
            keytabName = role + "-" + host + ".keytab";
        }

        URL url;
        try {
            url = new URL(request);
        } catch (MalformedURLException e) {
            throw new KrbException(e.getMessage());
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", true);

        try {
            httpConn.connect();

            if (httpConn.getResponseCode() != 200) {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
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
            throw new KrbException(e.getMessage());
        }
        System.out.println("Accept keytab file \"" + keytabName + "\" from server.");

        return new File(keytabName);
    }

    public String getHostRoles() throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getHadminBaseURL() + "hostroles");
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "GET", true);

        String response;
        try {
            httpConn.setDoInput(true);
            httpConn.connect();

            if (httpConn.getResponseCode() == 200) {
                response = HasClientUtil.getResponse(httpConn);
            } else {
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            LOG.error("IO error occurred." + e.getMessage());
            throw new KrbException("IO error occurred.", e);
        }
        return response;
    }

    public String getPrincipal(String principalName) throws KrbException {
        HttpURLConnection httpConn;

        URL url;
        try {
            url = new URL(getKadminBaseURL() + "getprincipal?principal=" + principalName);
        } catch (MalformedURLException e) {
            throw new KrbException("Failed to create a URL object.", e);
        }

        httpConn = HasClientUtil.createConnection(hasConfig, url, "POST", true);

        String response;
        try {
            httpConn.setDoInput(true);
            httpConn.connect();

            OutputStream out = httpConn.getOutputStream();
            out.write(principalName.getBytes());
            out.flush();
            out.close();

            if (httpConn.getResponseCode() == 200) {
                response = HasClientUtil.getResponse(httpConn);
                LOG.info(response);
            } else {
                LOG.info(HasClientUtil.getResponse(httpConn));
                throw new KrbException(HasClientUtil.getResponse(httpConn));
            }
        } catch (IOException e) {
            LOG.error("IO error occurred.", e);
            throw new KrbException("IO error occurred.", e);
        }

        return response;
    }
}
