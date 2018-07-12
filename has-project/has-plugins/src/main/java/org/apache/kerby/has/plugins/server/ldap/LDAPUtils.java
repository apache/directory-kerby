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

import org.apache.kerby.has.plugins.server.ldap.conf.LDAPServerConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

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

    public static boolean doUserAuth(String user, String pwd) throws NamingException {
        Map env = new HashMap<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapServerConf.getLdapUrl());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, ldapServerConf.getBindDN());
        env.put(Context.SECURITY_CREDENTIALS, ldapServerConf.getBindPwd());
        DirContext ctx = null;

        boolean ret = false;
        try {
            ctx = new InitialDirContext(new Hashtable<>(env));
            SearchControls ctls = new SearchControls();
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            ctls.setReturningAttributes(new String[0]);
            ctls.setReturningObjFlag(true);

            String filter = String.format("(&(%s)(%s={0}))",
                    ldapServerConf.getUserFilter(), ldapServerConf.getUserNameAttr());
            NamingEnumeration enm = ctx.search(
                    ldapServerConf.getBaseDN(), filter, new String[]{user}, ctls);
            String dn = null;
            if (enm.hasMore()) {
                SearchResult result = (SearchResult) enm.next();
                dn = result.getNameInNamespace();
                System.out.println("dn: " + dn);
            }
            if (dn == null || enm.hasMore()) {
                throw new NamingException("Duplication user, Authentication failed");
            }
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, dn);
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, pwd);
            ctx.lookup(dn);
            enm.close();

            ret = true;
        } catch (NamingException e) {
            System.out.println(e.getMessage());
        } finally {
            ctx.close();
        }

        return ret;
    }
}
