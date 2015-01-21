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
import org.apache.kerberos.kerb.spec.kdc.TgsRep;
import org.apache.kerberos.kerb.spec.ticket.Ticket;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

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

        Assert.assertEquals(tgsRep.getPvno(), 5);
        Assert.assertEquals(tgsRep.getMsgType(), KrbMessageType.TGS_REP);
        Assert.assertEquals(tgsRep.getCrealm(), "DENYDC.COM");

        PrincipalName cname = tgsRep.getCname();
        Assert.assertEquals(cname.getNameType(), NameType.NT_PRINCIPAL);
        Assert.assertEquals(cname.getNameStrings().size(), 1);
        Assert.assertEquals(cname.getNameStrings().iterator().next(), "des");

        Ticket ticket = tgsRep.getTicket();
        Assert.assertEquals(ticket.getTktvno(), 5);
        Assert.assertEquals(ticket.getRealm(), "DENYDC.COM");
        PrincipalName sname = ticket.getSname();
        Assert.assertEquals(sname.getNameType(), NameType.NT_SRV_HST);
        Assert.assertEquals(sname.getNameStrings().size(), 2);
        Assert.assertEquals(sname.getNameStrings().get(0), "host");
        Assert.assertEquals(sname.getNameStrings().get(1), "xp1.denydc.com");
        //EncTicketPart encTicketPart = ticket.getEncPart();//FIXME null pointer!!
        //Assert.assertEquals(encTicketPart.getKey().getKeyType().getValue(), 23);
        //Assert.assertEquals(encTicketPart.getKey().getKvno(), 2);
        //TODO decode cipher

        //EncKdcRepPart encKdcRepPart = tgsRep.getEncPart();//FIXME null pointer!!
        //Assert.assertEquals(encKdcRepPart.getKey().getKeyType().getValue(), 3);
        //TODO decode cinpher
    }
}
