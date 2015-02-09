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
package org.apache.kerby.kerberos.kerb.codec.test;

import org.apache.kerby.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.common.NameType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.kdc.TgsRep;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test TgsRep message using a real 'correct' network packet captured from MS-AD to detective programming errors
 * and compatibility issues particularly regarding Kerberos crypto.
 */
public class TestTgsRepCodec {

    @Test
    public void test() throws IOException {
        byte[] bytes = CodecTestUtil.readBinaryFile("/tgsrep.token");
        TgsRep tgsRep = new TgsRep();
        tgsRep.decode(bytes);

        assertThat(tgsRep.getPvno()).isEqualTo(5);
        assertThat(tgsRep.getMsgType()).isEqualTo(KrbMessageType.TGS_REP);
        assertThat(tgsRep.getCrealm()).isEqualTo("DENYDC.COM");

        PrincipalName cName = tgsRep.getCname();
        assertThat(cName.getNameType()).isEqualTo(NameType.NT_PRINCIPAL);
        assertThat(cName.getNameStrings()).hasSize(1).contains("des");

        Ticket ticket = tgsRep.getTicket();
        assertThat(ticket.getTktvno()).isEqualTo(5);
        assertThat(ticket.getRealm()).isEqualTo("DENYDC.COM");
        PrincipalName sName = ticket.getSname();
        assertThat(sName.getNameType()).isEqualTo(NameType.NT_SRV_HST);
        assertThat(sName.getNameStrings()).hasSize(2)
                .contains("host", "xp1.denydc.com");
        //FIXME
        //EncTicketPart encTicketPart = ticket.getEncPart();
        //assertThat(encTicketPart.getKey().getKeyType().getValue()).isEqualTo(23);
        //assertThat(encTicketPart.getKey().getKvno()).isEqualTo(2);

        //EncKdcRepPart encKdcRepPart = tgsRep.getEncPart();
        //assertThat(encKdcRepPart.getKey().getKeyType().getValue()).isEqualTo(3);
    }
}
