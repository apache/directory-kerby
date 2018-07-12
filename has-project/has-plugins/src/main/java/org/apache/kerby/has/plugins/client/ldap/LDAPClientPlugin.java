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
package org.apache.kerby.has.plugins.client.ldap;

import org.apache.kerby.has.client.AbstractHasClientPlugin;
import org.apache.kerby.has.client.HasLoginException;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.ini4j.Wini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Date;

public class LDAPClientPlugin extends AbstractHasClientPlugin {
    public static final Logger LOG = LoggerFactory.getLogger(LDAPClientPlugin.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public String getLoginType() {
        return "LDAP";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doLogin(AuthToken authToken) throws HasLoginException {
        String user = System.getenv("LDAP_USER");
        String pwd = System.getenv("LDAP_PWD");
        if (user == null || pwd == null) {
            String ldapConfigDir = System.getenv("HAS_CONF_DIR");
            if (ldapConfigDir == null) {
                LOG.error("Get LDAP User/Secret failed, "
                        + "you can set them using export system environment(User/Secret),"
                        + "or export HAS_CONF_DIR which has a credential.xml file");
            } else {
                try {
                    String confFile = ldapConfigDir + "/ldap-client.ini";
                    Wini ini = new Wini(new File(confFile));
                    user = ini.get("user", "ldap_user");
                    pwd = ini.get("user", "ldap_pwd");
                } catch (Exception e) {
                    LOG.error("parser ldap ini failed", e);
                }

                LOG.debug("Get LDAP User/Secret from " + ldapConfigDir
                        + "/ldap-client.ini, user:" + user);
            }
        } else {
            LOG.debug("Get LDAP User/Secret from sys environment, user:" + user);
        }

        if (user == null) {
            user = System.getProperty("user.name");
        }

        if (user == null || pwd == null) {
            String errMsg = "Get LDAP User/Secret failed, "
                    + "you can set them using export system environment(User/Secret),"
                    + "or export HAS_CONF_DIR which has a credential.xml file";
            LOG.error(errMsg);
            throw new HasLoginException(errMsg);
        }

        authToken.setIssuer("has");

        final Date now = new Date(new Date().getTime() / 1000 * 1000);
        authToken.setIssueTime(now);
        // Set expiration in 60 minutes
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        authToken.addAttribute("ldap_user", user);
        authToken.addAttribute("ldap_pwd", pwd);
        authToken.addAttribute("passPhrase", pwd);
    }

}
