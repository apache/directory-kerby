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

        Assert.assertEquals(5, tgsRep.getPvno());
        Assert.assertEquals(KrbMessageType.TGS_REP, tgsRep.getMsgType());
        Assert.assertEquals("DENYDC.COM", tgsRep.getCrealm());

        PrincipalName cName = tgsRep.getCname();
        Assert.assertEquals(NameType.NT_PRINCIPAL, cName.getNameType());
        Assert.assertEquals(1, cName.getNameStrings().size());
        Assert.assertEquals("des", cName.getNameStrings().get(0));

        Ticket ticket = tgsRep.getTicket();
        Assert.assertEquals(5, ticket.getTktvno());
        Assert.assertEquals("DENYDC.COM", ticket.getRealm());
        PrincipalName sName = ticket.getSname();
        Assert.assertEquals(NameType.NT_SRV_HST, sName.getNameType());
        Assert.assertEquals(2, sName.getNameStrings().size());
        Assert.assertEquals("host", sName.getNameStrings().get(0));
        Assert.assertEquals("xp1.denydc.com", sName.getNameStrings().get(1));
        //FIXME
        //EncTicketPart encTicketPart = ticket.getEncPart();
        //Assert.assertEquals(23, encTicketPart.getKey().getKeyType().getValue());
        //Assert.assertEquals(2, encTicketPart.getKey().getKvno());

        //EncKdcRepPart encKdcRepPart = tgsRep.getEncPart();
        //Assert.assertEquals(3, encKdcRepPart.getKey().getKeyType().getValue());
    }
}
