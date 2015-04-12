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

import org.apache.kerby.kerberos.kdc.impl.NettyKdcServerImpl;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.junit.Assert;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class KerbyKdcTest extends KdcTestBase {

    @Override
    protected void prepareKdcServer() throws Exception {
        super.prepareKdcServer();
        kdcServer.setInnerKdcImpl(new NettyKdcServerImpl());
    }

    @Override
    protected void createPrincipals() {
        super.createPrincipals();
        kdcServer.createPrincipal(clientPrincipal, TEST_PASSWORD);
    }

    protected void performKdcTest() throws Exception {
        kdcServer.start();

        File testDir = new File(System.getProperty("test.dir", "target"));
        File testConfDir = new File(testDir, "conf");
        krbClnt.setConfDir(testConfDir);
        krbClnt.init();

        TgtTicket tgt;
        ServiceTicket tkt;

        try {
            tgt = krbClnt.requestTgtWithPassword(clientPrincipal, TEST_PASSWORD);
            assertThat(tgt).isNotNull();

            tkt = krbClnt.requestServiceTicketWithTgt(tgt, serverPrincipal);
            assertThat(tkt).isNotNull();
        } catch (Exception e) {
            System.out.println("Exception occurred with good password");
            e.printStackTrace();
            Assert.fail();
        }
    }
}