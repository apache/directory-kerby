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
package org.apache.kerby.kerberos.kerb.codec;

import org.apache.kerby.kerberos.kerb.spec.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.base.NameType;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test AsRep message using a real 'correct' network packet captured from MS-AD to detective programming errors
 * and compatibility issues particularly regarding Kerberos crypto.
 */
public class TestAsRepCodec {

    @Test
    public void test() throws IOException {
        byte[] bytes = CodecTestUtil.readBinaryFile("/asrep.token");
        ByteBuffer asRepToken = ByteBuffer.wrap(bytes);

        AsRep asRep = new AsRep();
        asRep.decode(asRepToken);

        assertThat(asRep.getPvno()).isEqualTo(5);
        assertThat(asRep.getMsgType()).isEqualTo(KrbMessageType.AS_REP);
        assertThat(asRep.getCrealm()).isEqualTo("DENYDC.COM");

        PrincipalName cName = asRep.getCname();
        assertThat(cName.getNameType()).isEqualTo(NameType.NT_PRINCIPAL);
        assertThat(cName.getNameStrings()).hasSize(1).contains("u5");

        Ticket ticket = asRep.getTicket();
        assertThat(ticket.getTktvno()).isEqualTo(5);
        assertThat(ticket.getRealm()).isEqualTo("DENYDC.COM");
        PrincipalName sName = ticket.getSname();
        assertThat(sName.getNameType()).isEqualTo(NameType.NT_SRV_INST);
        assertThat(sName.getNameStrings()).hasSize(2)
                .contains("krbtgt", "DENYDC.COM");
        //FIXME
        //EncTicketPart encTicketPart = ticket.getEncPart();
        //assertThat(encTicketPart.getKey().getKvno()).isEqualTo(2);
        //assertThat(encTicketPart.getKey().getKeyType().getValue()).isEqualTo(0x0017);

        //EncKdcRepPart encKdcRepPart = asRep.getEncPart();
        //assertThat(encKdcRepPart.getKey().getKeyType().getValue()).isEqualTo(0x0017);
        //assertThat(encKdcRepPart.getKey().getKvno()).isEqualTo(7);
    }
}
