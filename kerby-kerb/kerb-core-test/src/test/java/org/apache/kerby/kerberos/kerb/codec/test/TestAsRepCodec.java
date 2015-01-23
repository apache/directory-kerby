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
import org.apache.kerby.kerberos.kerb.spec.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

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

        Assert.assertEquals(5, asRep.getPvno());
        Assert.assertEquals(KrbMessageType.AS_REP, asRep.getMsgType());
        Assert.assertEquals("DENYDC.COM", asRep.getCrealm());

        PrincipalName cName = asRep.getCname();
        Assert.assertEquals(NameType.NT_PRINCIPAL, cName.getNameType());
        Assert.assertEquals(1, cName.getNameStrings().size());
        Assert.assertEquals("u5", cName.getNameStrings().get(0));

        Ticket ticket = asRep.getTicket();
        Assert.assertEquals(5, ticket.getTktvno());
        Assert.assertEquals("DENYDC.COM", ticket.getRealm());
        PrincipalName sName = ticket.getSname();
        Assert.assertEquals(NameType.NT_SRV_INST, sName.getNameType());
        Assert.assertEquals(2, sName.getNameStrings().size());
        Assert.assertEquals("krbtgt", sName.getNameStrings().get(0));
        Assert.assertEquals("DENYDC.COM", sName.getNameStrings().get(1));
        //FIXME
        //EncTicketPart encTicketPart = ticket.getEncPart();
        //Assert.assertEquals(2, encTicketPart.getKey().getKvno());
        //Assert.assertEquals(0x0017, encTicketPart.getKey().getKeyType().getValue());

        //EncKdcRepPart encKdcRepPart = asRep.getEncPart();
        //Assert.assertEquals(0x0017, encKdcRepPart.getKey().getKeyType().getValue());
        //Assert.assertEquals(7, encKdcRepPart.getKey().getKvno());
    }
}
