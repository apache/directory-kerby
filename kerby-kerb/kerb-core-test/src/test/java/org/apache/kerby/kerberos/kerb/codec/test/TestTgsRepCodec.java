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

import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.spec.kdc.EncTgsRepPart;
import org.apache.kerby.kerberos.kerb.spec.kdc.TgsRep;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test TgsRep message using a real 'correct' network packet captured from MS-AD to detective programming errors
 * and compatibility issues particularly regarding Kerberos crypto.
 */
public class TestTgsRepCodec extends TestMessageCodec{

    @Test
    public void test() throws Exception {
        byte[] bytes = readBinaryFile("/tgsrep.token");
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

        //test for encrypted data
        Keytab keytab = getDefaultKeytab();
        cName.setRealm(tgsRep.getCrealm());
        EncryptionKey key = keytab.getKey(cName, EncryptionType.DES_CBC_MD5);
        EncKdcRepPart encKdcRepPart = EncryptionUtil.unseal(tgsRep.getEncryptedEncPart(), key,
                KeyUsage.TGS_REP_ENCPART_SESSKEY, EncTgsRepPart.class);

        LastReq lastReq = encKdcRepPart.getLastReq();
        assertThat(lastReq.getElements()).hasSize(1);
        LastReqEntry lastReqEntry = lastReq.getElements().iterator().next();
        assertThat(lastReqEntry.getLrType()).isEqualTo(LastReqType.NONE);
        assertThat(lastReqEntry.getLrValue().getTime()).isEqualTo(parseDateByDefaultFormat("20050816094029"));

        assertThat(encKdcRepPart.getNonce()).isEqualTo(197296424);

        byte[] ticketFlags = new byte[]{64, -96, 0, 0};
        assertThat(encKdcRepPart.getFlags().getValue()).isEqualTo(ticketFlags);

        assertThat(encKdcRepPart.getAuthTime().getTime()).isEqualTo(parseDateByDefaultFormat("20050816094029"));
        assertThat(encKdcRepPart.getStartTime().getTime()).isEqualTo(parseDateByDefaultFormat("20050816094029"));
        assertThat(encKdcRepPart.getEndTime().getTime()).isEqualTo(parseDateByDefaultFormat("20050816194029"));
        assertThat(encKdcRepPart.getRenewTill().getTime()).isEqualTo(parseDateByDefaultFormat("20050823094029"));

        assertThat(encKdcRepPart.getSrealm()).isEqualTo("DENYDC.COM");

        PrincipalName encSName = encKdcRepPart.getSname();
        assertThat(encSName.getName()).isEqualTo("host/xp1.denydc.com");
        assertThat(encSName.getNameType()).isEqualTo(NameType.NT_SRV_HST);
        assertThat(encSName.getNameStrings()).hasSize(2)
                .contains("host")
                .contains("xp1.denydc.com");
    }
}
