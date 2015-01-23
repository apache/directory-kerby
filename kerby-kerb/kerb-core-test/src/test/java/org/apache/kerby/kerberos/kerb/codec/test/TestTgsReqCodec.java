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
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.SimpleTimeZone;

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

        Assert.assertEquals(5, tgsReq.getPvno());
        Assert.assertEquals(KrbMessageType.TGS_REQ, tgsReq.getMsgType());

        PaData paData = tgsReq.getPaData();
        Assert.assertEquals(1, paData.getElements().size());
        PaDataEntry entry = paData.getElements().iterator().next();
        Assert.assertEquals(PaDataType.TGS_REQ, entry.getPaDataType());

        //request body
        KdcReqBody body = tgsReq.getReqBody();
        Assert.assertEquals(0, body.getKdcOptions().getPadding());
        byte[] kdcOptionsValue = {64, (byte) 128, 0, 0};
        Assert.assertArrayEquals(kdcOptionsValue, body.getKdcOptions().getValue());

        Assert.assertEquals("DENYDC.COM", body.getRealm());

        PrincipalName sName = body.getSname();
        Assert.assertEquals(NameType.NT_SRV_HST, sName.getNameType());
        Assert.assertEquals(2, sName.getNameStrings().size());
        Assert.assertEquals("host", sName.getNameStrings().get(0));
        Assert.assertEquals("xp1.denydc.com", sName.getNameStrings().get(1));

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse("20370913024805");
        Assert.assertEquals(date.getTime(), body.getTill().getTime());

        Assert.assertEquals(197296424, body.getNonce());

        List<EncryptionType> eTypes = body.getEtypes();
        Assert.assertEquals(7, eTypes.size());
        Assert.assertEquals(0x0017, eTypes.get(0).getValue());
        //Assert.assertEquals(-133, eTypes.get(1).getValue());//FIXME
        //Assert.assertEquals(-128, eTypes.get(2).getValue());//FIXME
        Assert.assertEquals(0x0003, eTypes.get(3).getValue());
        Assert.assertEquals(0x0001, eTypes.get(4).getValue());
        Assert.assertEquals(0x0018, eTypes.get(5).getValue());
        //Assert.assertEquals(-135, eTypes.get(6).getValue());//FIXME
    }
}
