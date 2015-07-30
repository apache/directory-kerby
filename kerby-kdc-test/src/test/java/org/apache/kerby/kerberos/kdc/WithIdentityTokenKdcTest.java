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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WithIdentityTokenKdcTest extends WithTokenKdcTestBase {

    @Test
    public void testKdc() throws Exception {

        prepareToken(null);
        createCredentialCache(getClientPrincipal(), getClientPassword());

        TgtTicket tgt = null;
        try {
            tgt = getKrbClient().requestTgtWithToken(getKrbToken(),
                    getcCacheFile().getPath());
        } catch (KrbException e) {
            assertThat(e.getMessage().contains("timeout")).isTrue();
            return;
        }
        verifyTicket(tgt);

        ServiceTicket tkt = getKrbClient().requestServiceTicketWithTgt(tgt,
                getServerPrincipal());
        verifyTicket(tkt);
    }
}