/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.plugins.server.ldap.conf;

import org.ini4j.Wini;

import java.io.File;

public class LDAPServerConf {

    private String userFilter = "objectclass=*";
    private String userNameAttr = "sn";
    private String ldapUrl = null;
    private String baseDN = null;
    private String bindDN = null;
    private String bindPwd = null;

    public LDAPServerConf(String confDir) throws Exception {
        if (confDir == null) {
            throw new RuntimeException("ldap server conf dir is null");
        }

        String confFile = confDir + "/ldap-server.ini";
        Wini ini = new Wini(new File(confFile));
        userFilter = ini.get("users", "user_filter");
        userNameAttr = ini.get("users", "user_name_attr");
        ldapUrl = ini.get("ldap", "ldap_url");
        baseDN = ini.get("ldap", "base_dn");
        bindDN = ini.get("ldap", "bind_dn");
        bindPwd = ini.get("ldap", "bind_password");
    }

    public String getUserFilter() {
        return userFilter;
    }

    public void setUserFilter(String userFilter) {
        this.userFilter = userFilter;
    }

    public String getUserNameAttr() {
        return userNameAttr;
    }

    public void setUserNameAttr(String userNameAttr) {
        this.userNameAttr = userNameAttr;
    }

    public String getLdapUrl() {
        return ldapUrl;
    }

    public void setLdapUrl(String ldapUrl) {
        this.ldapUrl = ldapUrl;
    }

    public String getBaseDN() {
        return baseDN;
    }

    public void setBaseDN(String baseDN) {
        this.baseDN = baseDN;
    }

    public String getBindDN() {
        return bindDN;
    }

    public void setBindDN(String bindDN) {
        this.bindDN = bindDN;
    }

    public String getBindPwd() {
        return bindPwd;
    }

    public void setBindPwd(String bindPwd) {
        this.bindPwd = bindPwd;
    }
}
