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

import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.SimpleTimeZone;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test AsReq message using a real 'correct' network packet captured from MS-AD to detective programming errors
 * and compatibility issues particularly regarding Kerberos crypto.
 */
public class TestAsReqCodec {

    @Test
    public void test() throws IOException, ParseException {
        byte[] bytes = CodecTestUtil.readBinaryFile("/asreq.token");
        ByteBuffer asReqToken = ByteBuffer.wrap(bytes);

        AsReq asReq = new AsReq();
        asReq.decode(asReqToken);

        assertThat(asReq.getPvno()).isEqualTo(5);
        assertThat(asReq.getMsgType()).isEqualTo(KrbMessageType.AS_REQ);

        PaData paData = asReq.getPaData();
        PaDataEntry encTimestampEntry = paData.findEntry(PaDataType.ENC_TIMESTAMP);
        assertThat(encTimestampEntry.getPaDataType()).isEqualTo(PaDataType.ENC_TIMESTAMP);
        assertThat(encTimestampEntry.getPaDataValue()).isEqualTo(Arrays.copyOfRange(bytes, 33, 96));
        PaDataEntry pacRequestEntry = paData.findEntry(PaDataType.PAC_REQUEST);
        assertThat(pacRequestEntry.getPaDataType()).isEqualTo(PaDataType.PAC_REQUEST);
        assertThat(pacRequestEntry.getPaDataValue()).isEqualTo(Arrays.copyOfRange(bytes, 108, 115));

        KdcReqBody body = asReq.getReqBody();
        assertThat(body.getKdcOptions().getPadding()).isEqualTo(0);
        assertThat(body.getKdcOptions().getValue()).isEqualTo(Arrays.copyOfRange(bytes, 126, 130));
        PrincipalName cName = body.getCname();
        assertThat(cName.getNameType()).isEqualTo(NameType.NT_PRINCIPAL);
        assertThat(cName.getName()).isEqualTo("des");
        assertThat(body.getRealm()).isEqualTo("DENYDC");
        PrincipalName sName = body.getSname();
        assertThat(sName.getNameType()).isEqualTo(NameType.NT_SRV_INST);
        assertThat(sName.getNameStrings()).hasSize(2)
                .contains("krbtgt", "DENYDC");

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse("20370913024805");
        assertThat(body.getTill().getTime()).isEqualTo(date.getTime());
        assertThat(body.getRtime().getTime()).isEqualTo(date.getTime());

        assertThat(body.getNonce()).isEqualTo(197451134);

        List<EncryptionType> types = body.getEtypes();
        assertThat(types).hasSize(7);
        assertThat(types.get(0).getValue()).isEqualTo(0x0017);
        //assertThat(types.get(1).getValue()).isEqualTo(0xff7b);//FIXME
        //assertThat(types.get(2).getValue()).isEqualTo(0x0080);//FIXME
        assertThat(types.get(3).getValue()).isEqualTo(0x0003);
        assertThat(types.get(4).getValue()).isEqualTo(0x0001);
        assertThat(types.get(5).getValue()).isEqualTo(0x0018);
        //assertThat(types.get(6).getValue()).isEqualTo(0xff79);//FIXME

        List<HostAddress> hostAddress = body.getAddresses().getElements();
        assertThat(hostAddress).hasSize(1);
        assertThat(hostAddress.get(0).getAddrType()).isEqualTo(HostAddrType.ADDRTYPE_NETBIOS);
    }
}
