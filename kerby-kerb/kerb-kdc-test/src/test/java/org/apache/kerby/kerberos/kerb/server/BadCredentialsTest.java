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

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.Assert;
import org.junit.Test;

/**
 * Send some unknown principals, bad passwords etc. to the KDC to check that it is handled correctly.
 */
public class BadCredentialsTest extends KdcTestBase {

    @Test
    public void testUnknownClientPrincipal() {
        String principal = "unknown@" + TestKdcServer.KDC_REALM;
        try {
            getKrbClient().requestTgt(principal, getClientPassword());
        } catch (KrbException ex) {
            Assert.assertEquals(KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN, ex.getKrbErrorCode());
        }
    }

    @Test
    public void testUnknownClientPassword() {
        try {
            getKrbClient().requestTgt(getClientPrincipal(), "badpass");
        } catch (KrbException ex) {
            Assert.assertEquals(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY, ex.getKrbErrorCode());
        }
    }

    @Test
    public void testUnknownServicePrincipal() {
        try {
            TgtTicket tgtTicket =
                getKrbClient().requestTgt(getClientPrincipal(), getClientPassword());

            String serverPrincipal = "unknown/" + getHostname() + "@" + TestKdcServer.KDC_REALM;
            getKrbClient().requestSgt(tgtTicket, serverPrincipal);
        } catch (KrbException ex) {
            Assert.assertEquals(KrbErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN, ex.getKrbErrorCode());
        }
    }

}
