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

import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.Test;

public class CacheFileTest extends KdcTestBase {

    @Test
    public void testStoringSGT() throws Exception {

        TgtTicket tgt = getKrbClient().requestTgt(getClientPrincipal(),
                                        getClientPassword());
        assertThat(tgt).isNotNull();

        SgtTicket tkt = getKrbClient().requestSgt(tgt, getServerPrincipal());
        assertThat(tkt).isNotNull();

        File ccFile = new File("target/cache.cc");
        if (ccFile.exists()) {
            ccFile.delete();
        }

        try {
            // Test storing the SGT and not the TGT
            getKrbClient().storeTicket(tkt, ccFile);
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}
