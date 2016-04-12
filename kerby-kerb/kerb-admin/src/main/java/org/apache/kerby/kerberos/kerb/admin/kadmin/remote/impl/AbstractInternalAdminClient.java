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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminContext;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminSetting;

/**
 * A krb client API for applications to interact with KDC
 */
public abstract class AbstractInternalAdminClient
                                    implements InternalAdminClient {
    private AdminContext context;
    private final AdminSetting krbSetting;

    public AbstractInternalAdminClient(AdminSetting krbSetting) {
        this.krbSetting = krbSetting;
    }

    protected AdminContext getContext() {
        return context;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AdminSetting getSetting() {
        return krbSetting;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init() throws KrbException {
        context = new AdminContext();
        context.init(krbSetting);
    }

    /**
     * Fix principal name.
     *
     * @param principal The principal name
     * @return The fixed principal
     */
    protected String fixPrincipal(String principal) {
        if (!principal.contains("@")) {
            principal += "@" + krbSetting.getKdcRealm();
        }
        return principal;
    }
}
