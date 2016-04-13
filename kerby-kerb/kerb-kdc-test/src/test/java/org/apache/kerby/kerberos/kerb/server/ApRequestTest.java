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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.request.ApRequest;
import org.apache.kerby.kerberos.kerb.response.ApResponse;
import org.apache.kerby.kerberos.kerb.type.ap.ApRep;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class ApRequestTest extends KdcTestBase {

    @Test
    public void test() throws IOException, KrbException {

        TgtTicket tgt = null;
        SgtTicket tkt = null;

        try {
            tgt = getKrbClient().requestTgt(getClientPrincipal(),
                    getClientPassword());
            assertThat(tgt).isNotNull();

            tkt = getKrbClient().requestSgt(tgt, getServerPrincipal());
            assertThat(tkt).isNotNull();
        } catch (Exception e) {
            System.out.println("Exception occurred with good password");
            e.printStackTrace();
            Assert.fail();
        }

        ApRequest apRequest = new ApRequest(new PrincipalName(getClientPrincipal()), tkt);
        ApReq apReq = apRequest.getApReq();

        assertThat(apReq.getPvno()).isEqualTo(5);
        assertThat(apReq.getMsgType()).isEqualTo(KrbMessageType.AP_REQ);
        assertThat(apReq.getAuthenticator().getCname()).isEqualTo(tgt.getClientPrincipal());
        assertThat(apReq.getAuthenticator().getCrealm()).isEqualTo(tgt.getRealm());

        EncryptionKey encryptedKey = getKdcServer().getKadmin().getPrincipal(
                getServerPrincipal()).getKey(tkt.getTicket().getEncryptedEncPart().getEType());
        ApResponse apResponse = new ApResponse(apReq, encryptedKey);
        ApRep apRep = apResponse.getApRep();
        assertThat(apRep.getPvno()).isEqualTo(5);
        assertThat(apRep.getMsgType()).isEqualTo(KrbMessageType.AP_REP);
    }
}
