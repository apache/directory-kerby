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
package org.apache.kerby.kerberos.kdc;

import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.server.TestKdcServer;
import org.junit.Test;

import java.io.File;
import java.net.URL;

public class MultiKdcsTest extends KerbyKdcTest {

    @Override
    protected void setUpKdcServer() throws Exception {

        URL krb5FileUrl = this.getClass().getResource("/krb5-multikdc.conf");
        File krb5File = new File(krb5FileUrl.toURI());
        KrbConfig krbConfig = new KrbConfig();
        krbConfig.addKrb5Config(krb5File);
        SimpleKdcServer kdcServer = new TestKdcServer(krb5File.getParentFile(), krbConfig);
        setKdcServer(kdcServer);
        configKdcSeverAndClient();
        prepareKdc();
        kdcServer.start();
    }

    @Test
    public void testKdc() throws Exception {
        performKdcTest();
    }
}
