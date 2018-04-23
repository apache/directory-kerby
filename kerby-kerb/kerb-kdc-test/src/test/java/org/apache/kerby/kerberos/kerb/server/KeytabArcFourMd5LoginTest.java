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
package org.apache.kerby.kerberos.kerb.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.Test;

public class KeytabArcFourMd5LoginTest extends LoginTestBase {

    @Override
    protected void setUpKdcServer() throws Exception {
        KdcConfig config = new KdcConfig();
        config.setString(KdcConfigKey.ENCRYPTION_TYPES, "arcfour-hmac");
        SimpleKdcServer kdcServer = new TestKdcServer(allowTcp(), allowUdp(), config, new BackendConfig());
        super.setKdcServer(kdcServer);

        configKdcSeverAndClient();

        prepareKdc();

        kdcServer.start();
    }

    @Test
    public void testLogin() throws Exception {
        KrbClient client = super.getKrbClient();
        client.getKrbConfig().setString(KrbConfigKey.PERMITTED_ENCTYPES, "arcfour-hmac");

        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, getClientPrincipal());
        requestOptions.add(KrbOption.USE_KEYTAB, true);

        File keytab = new File(getTestDir(), "test-client.keytab");
        requestOptions.add(KrbOption.KEYTAB_FILE, keytab);

        getKdcServer().exportPrincipal(getClientPrincipal(), keytab);

        TgtTicket tgt = client.requestTgt(requestOptions);
        assertThat(tgt).isNotNull();

        SgtTicket tkt = client.requestSgt(tgt, getServerPrincipal());
        assertThat(tkt).isNotNull();

        keytab.delete();

    }
}