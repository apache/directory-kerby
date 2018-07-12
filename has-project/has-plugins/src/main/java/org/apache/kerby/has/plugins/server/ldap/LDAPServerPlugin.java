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

import org.apache.kerby.has.server.AbstractHasServerPlugin;
import org.apache.kerby.has.server.HasAuthenException;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LDAPServerPlugin extends AbstractHasServerPlugin {
    public static final Logger LOG = LoggerFactory.getLogger(LDAPServerPlugin.class);

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
    public void doAuthenticate(AuthToken userToken, AuthToken authToken) throws HasAuthenException {

        String user = (String) userToken.getAttributes().get("ldap_user");
        String pwd = (String) userToken.getAttributes().get("ldap_pwd");
        if (user == null || pwd == null) {
            LOG.error("LDAP: user or pwd is null");
            throw new HasAuthenException("LDAP: user or pwd is null");
        }

        try {
            if (LDAPUtils.doUserAuth(user, pwd)) {
                authToken.setIssuer(userToken.getIssuer());
                authToken.setSubject(user);
                authToken.setExpirationTime(userToken.getExpiredTime());
                authToken.addAttribute("passPhrase", pwd);
            } else {
                throw new HasAuthenException("LDAP do user auth failed");
            }
        } catch (Exception e) {
            throw new HasAuthenException("LDAP do user auth failed", e);
        }
    }
}
