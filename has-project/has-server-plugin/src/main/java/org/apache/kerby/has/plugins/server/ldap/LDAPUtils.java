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
package org.apache.kerby.has.plugins.server.ldap;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.password.PasswordUtil;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.plugins.server.ldap.conf.LDAPServerConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class LDAPUtils {
    public static final Logger LOG = LoggerFactory.getLogger(LDAPUtils.class);

    private static String ldapServerConfDir = "/etc/has/";
    private static LDAPServerConf ldapServerConf = null;
    static {
        try {
            ldapServerConf = new LDAPServerConf(ldapServerConfDir);
        } catch (Exception e) {
            LOG.error("load conf failed,", e);
        }
    }

    public static boolean doUserAuth(String user, String pwd)
        throws HasException, IOException, LdapInvalidAttributeValueException {
        LdapNetworkConnection connection = new LdapNetworkConnection(
            ldapServerConf.getHost(), Integer.parseInt(ldapServerConf.getPort()));
        try {
            connection.bind(ldapServerConf.getBindDN(), ldapServerConf.getBindPwd());
        } catch (LdapException e) {
            connection.close();
            throw new HasException("Failed to bind. " + e.getMessage());
        }
        Dn dn;
        try {
            dn = new Dn(new Rdn(ldapServerConf.getUserNameAttr(), user),
                new Dn(ldapServerConf.getBaseDN()));
        } catch (LdapInvalidDnException e) {
            connection.close();
            throw new HasException(e.getMessage());
        }
        Entry entry;
        try {
            entry = connection.lookup(dn);
        } catch (LdapException e) {
            throw new HasException(e.getMessage());
        } finally {
            connection.close();
        }

        if (entry == null) {
            throw new HasException("Please check your user name: " + user);
        }
        try {
            if (PasswordUtil.compareCredentials(pwd.getBytes(), entry.get("userpassword").getBytes())) {
                return true;
            } else {
                throw new HasException("Wrong user password.");
            }
        } catch (LdapInvalidAttributeValueException e) {
            throw new HasException(e.getMessage());
        }
    }
}
