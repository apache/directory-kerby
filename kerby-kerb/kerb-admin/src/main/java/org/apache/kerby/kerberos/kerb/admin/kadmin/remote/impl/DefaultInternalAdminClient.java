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
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminHandler;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminSetting;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminUtil;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;

import java.io.IOException;

/**
 * A default krb client implementation.
 */
public class DefaultInternalAdminClient extends AbstractInternalAdminClient {

    private DefaultAdminHandler adminHandler;
    private KrbTransport transport;

    public DefaultInternalAdminClient(AdminSetting krbSetting) {
        super(krbSetting);
    }

    public AdminHandler getAdminHanlder() {
        return adminHandler;
    }

    public KrbTransport getTransport() {
        return transport;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init() throws KrbException {
        super.init();

        this.adminHandler = new DefaultAdminHandler();
        adminHandler.init(getContext());

        TransportPair tpair = AdminUtil.getTransportPair(getSetting());
        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(getSetting().getTimeout());
        try {
            transport = network.connect(tpair);
        } catch (IOException e) {
            throw new KrbException("Failed to create transport", e);
        }
    }
}
