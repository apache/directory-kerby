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
package org.apache.kerby.has.plugins.client.mysql;

import org.apache.kerby.has.client.AbstractHasClientPlugin;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

public class MySQLHasClientPlugin extends AbstractHasClientPlugin {
    private static final Logger LOG = LoggerFactory.getLogger(MySQLHasClientPlugin.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public String getLoginType() {
        return "MySQL";
    }

    @Override
    protected void doLogin(AuthToken authToken) {

        //Get the user info from env
        String userName = System.getenv("userName");
        String password = System.getenv("password");
        LOG.debug("Get the user info successfully.");

        authToken.setIssuer("has");
        authToken.setSubject(userName);

        final Date now = new Date(System.currentTimeMillis() / 1000 * 1000);
        authToken.setIssueTime(now);
        // Set expiration in 60 minutes
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        authToken.addAttribute("user", userName);
        authToken.addAttribute("secret", password);

        authToken.addAttribute("passPhrase", userName + password);
    }
}
