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

import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.common.NameType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.spec.kdc.TgsReq;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.junit.Test;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.SimpleTimeZone;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test TgsReq message using a real 'correct' network packet captured from MS-AD to detective programming errors
 * and compatibility issues particularly regarding Kerberos crypto.
 */
public class TestTgsReqCodec {

    @Test
    public void test() throws IOException, ParseException {
        byte[] bytes = CodecTestUtil.readBinaryFile("/tgsreq.token");
        TgsReq tgsReq = new TgsReq();
        tgsReq.decode(bytes);

        assertThat(tgsReq.getPvno()).isEqualTo(5);
        assertThat(tgsReq.getMsgType()).isEqualTo(KrbMessageType.TGS_REQ);

        PaData paData = tgsReq.getPaData();
        assertThat(paData.getElements()).hasSize(1);
        PaDataEntry entry = paData.getElements().iterator().next();
        assertThat(entry.getPaDataType()).isEqualTo(PaDataType.TGS_REQ);

        //request body
        KdcReqBody body = tgsReq.getReqBody();
        assertThat(body.getKdcOptions().getPadding()).isEqualTo(0);
        byte[] kdcOptionsValue = {64, (byte) 128, 0, 0};
        assertThat(body.getKdcOptions().getValue()).isEqualTo(kdcOptionsValue);

        assertThat(body.getRealm()).isEqualTo("DENYDC.COM");

        PrincipalName sName = body.getSname();
        assertThat(sName.getNameType()).isEqualTo(NameType.NT_SRV_HST);
        assertThat(sName.getNameStrings()).hasSize(2)
                .contains("host", "xp1.denydc.com");

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse("20370913024805");
        assertThat(body.getTill().getTime()).isEqualTo(date.getTime());

        assertThat(body.getNonce()).isEqualTo(197296424);

        List<EncryptionType> eTypes = body.getEtypes();
        assertThat(eTypes).hasSize(7);
        assertThat(eTypes.get(0).getValue()).isEqualTo(0x0017);
        //assertThat(eTypes.get(1).getValue()).isEqualTo(-133);//FIXME
        //assertThat(eTypes.get(2).getValue()).isEqualTo(-128);//FIXME
        assertThat(eTypes.get(3).getValue()).isEqualTo(0x0003);
        assertThat(eTypes.get(4).getValue()).isEqualTo(0x0001);
        assertThat(eTypes.get(5).getValue()).isEqualTo(0x0018);
        //assertThat(eTypes.get(6).getValue()).isEqualTo(-135);//FIXME
    }
}
