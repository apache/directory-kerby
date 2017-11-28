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
package org.apache.kerby.has.common;

import org.apache.kerby.kerberos.kerb.common.Krb5Conf;

import java.io.File;

/**
 * AK configuration API.
 */
public class HasConfig extends Krb5Conf {
    private File confDir;

    public void setConfDir(File dir) {
        this.confDir = dir;
    }

    public File getConfDir() {
        return confDir;
    }

    public String getHttpsHost() {
        return getString(HasConfigKey.HTTPS_HOST, false, "HAS");
    }

    public String getHttpsPort() {
        return getString(HasConfigKey.HTTPS_PORT, false, "HAS");
    }

    public String getHttpHost() {
        return getString(HasConfigKey.HTTP_HOST, false, "HAS");
    }

    public String getHttpPort() {
        return getString(HasConfigKey.HTTP_PORT, false, "HAS");
    }

    public String getPluginName() {
        return getString(HasConfigKey.AUTH_TYPE, true, "PLUGIN");
    }

    public String getRealm() {
        return getString(HasConfigKey.REALM, false, "HAS");
    }

    public String getSslServerConf() {
        return getString(HasConfigKey.SSL_SERVER_CONF, true, "HAS");
    }

    public String getSslClientConf() {
        return getString(HasConfigKey.SSL_CLIENT_CONF, true, "HAS");
    }

    public String getFilterAuthType() {
        return getString(HasConfigKey.FILTER_AUTH_TYPE, true, "HAS");
    }

    public String getKerberosPrincipal() {
        return getString(HasConfigKey.KERBEROS_PRINCIPAL, false, "HAS");
    }

    public String getKerberosKeytab() {
        return getString(HasConfigKey.KERBEROS_KEYTAB, false, "HAS");
    }

    public String getKerberosNameRules() {
        return getString(HasConfigKey.KERBEROS_NAME_RULES, false, "HAS");
    }

    public String getAdminKeytab() {
        return getString(HasConfigKey.ADMIN_KEYTAB, false, "HAS");
    }

    public String getAdminKeytabPrincipal() {
        return getString(HasConfigKey.ADMIN_KEYTAB_PRINCIPAL, false, "HAS");
    }

    public String getEnableConf() {
        return getString(HasConfigKey.ENABLE_CONF, false, "HAS");
    }

    public String getSslClientCert() {
        return getString(HasConfigKey.SSL_CLIENT_CERT, true, "HAS");
    }
}
