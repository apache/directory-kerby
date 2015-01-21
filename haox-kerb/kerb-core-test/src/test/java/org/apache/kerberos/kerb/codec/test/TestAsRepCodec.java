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
package org.apache.kerberos.kerb.codec.test;

import org.apache.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerberos.kerb.spec.common.NameType;
import org.apache.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerberos.kerb.spec.kdc.AsRep;
import org.apache.kerberos.kerb.spec.kdc.EncKdcRepPart;
import org.apache.kerberos.kerb.spec.ticket.EncTicketPart;
import org.apache.kerberos.kerb.spec.ticket.Ticket;
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

        Assert.assertEquals(asRep.getPvno(), 5);
        Assert.assertEquals(asRep.getMsgType(), KrbMessageType.AS_REP);
        Assert.assertEquals(asRep.getCrealm(), "DENYDC.COM");

        PrincipalName cname = asRep.getCname();
        Assert.assertEquals(cname.getNameType(), NameType.NT_PRINCIPAL);
        Assert.assertEquals(cname.getNameStrings().size(), 1);
        Assert.assertEquals(cname.getNameStrings().get(0), "u5");

        Ticket ticket = asRep.getTicket();
        Assert.assertEquals(ticket.getTktvno(), 5);
        Assert.assertEquals(ticket.getRealm(), "DENYDC.COM");
        PrincipalName sname = ticket.getSname();
        Assert.assertEquals(sname.getNameType(), NameType.NT_SRV_INST);
        Assert.assertEquals(sname.getNameStrings().size(), 2);
        Assert.assertEquals(sname.getNameStrings().get(0), "krbtgt");
        Assert.assertEquals(sname.getNameStrings().get(1), "DENYDC.COM");
        //EncTicketPart encTicketPart = ticket.getEncPart();//FIXME
        //Assert.assertEquals(encTicketPart.getKey().getKvno(), 2);
        //Assert.assertEquals(encTicketPart.getKey().getKeyType().getValue(), 0x0017);
        //TODO decode cinpher

        //EncKdcRepPart encKdcRepPart = asRep.getEncPart();//FIXME
        //Assert.assertEquals(encKdcRepPart.getKey().getKeyType().getValue(), 0x0017);
        //Assert.assertEquals(encKdcRepPart.getKey().getKvno(), 7);
        //TODO decode cinpher
    }
}
