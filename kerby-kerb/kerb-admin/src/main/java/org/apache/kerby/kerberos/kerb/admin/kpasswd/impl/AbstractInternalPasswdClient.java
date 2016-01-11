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
package org.apache.kerby.kerberos.kerb.admin.kpasswd.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdSetting;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdContext;

/**
 * A krb client API for applications to interact with KDC
 */
public abstract class AbstractInternalPasswdClient
                                    implements InternalPasswdClient {
    private PasswdContext context;
    private final PasswdSetting passwdSetting;

    public AbstractInternalPasswdClient(PasswdSetting passwdSetting) {
        this.passwdSetting = passwdSetting;
    }

    protected PasswdContext getContext() {
        return context;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PasswdSetting getSetting() {
        return passwdSetting;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init() throws KrbException {
        context = new PasswdContext();
        context.init(passwdSetting);
    }

    /**
     * Fix principal name.
     *
     * @param principal The principal name
     * @return The fixed principal
     */
    protected String fixPrincipal(String principal) {
        if (!principal.contains("@")) {
            principal += "@" + passwdSetting.getKdcRealm();
        }
        return principal;
    }
}
