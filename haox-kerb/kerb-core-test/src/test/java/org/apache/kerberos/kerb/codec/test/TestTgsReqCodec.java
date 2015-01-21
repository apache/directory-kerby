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

import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerberos.kerb.spec.common.NameType;
import org.apache.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerberos.kerb.spec.kdc.KdcReqBody;
import org.apache.kerberos.kerb.spec.kdc.TgsReq;
import org.apache.kerberos.kerb.spec.pa.PaData;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaDataType;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
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

        Assert.assertEquals(tgsReq.getPvno(), 5);
        Assert.assertEquals(tgsReq.getMsgType(), KrbMessageType.TGS_REQ);

        PaData paData = tgsReq.getPaData();
        Assert.assertEquals(paData.getElements().size(), 1);
        PaDataEntry entry = paData.getElements().iterator().next();
        Assert.assertEquals(entry.getPaDataType(), PaDataType.TGS_REQ);
        //TODO Decode:padata-value

        //request body
        KdcReqBody body = tgsReq.getReqBody();
        Assert.assertEquals(body.getKdcOptions().getPadding(), 0);
        byte[] kdcOptionsValue = {64, (byte) 128, 0, 0};
        Assert.assertTrue(Arrays.equals(body.getKdcOptions().getValue(), kdcOptionsValue));

        Assert.assertEquals(body.getRealm(), "DENYDC.COM");

        PrincipalName sname = body.getSname();
        Assert.assertEquals(sname.getNameType(), NameType.NT_SRV_HST);
        Assert.assertEquals(sname.getNameStrings().size(), 2);
        Assert.assertEquals(sname.getNameStrings().get(0), "host");
        Assert.assertEquals(sname.getNameStrings().get(1), "xp1.denydc.com");

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse("20370913024805");
        Assert.assertEquals(tgsReq.getReqBody().getTill().getTime(), date.getTime());

        Assert.assertEquals(body.getNonce(), 197296424);

        List<EncryptionType> eTypes = body.getEtypes();
        Assert.assertEquals(eTypes.size(), 7);
        Assert.assertEquals(eTypes.get(0).getValue(), 23);
        //Assert.assertEquals(eTypes.get(1).getValue(), -133);//FIXME
        //Assert.assertEquals(eTypes.get(2).getValue(), -128);//FIXME
        Assert.assertEquals(eTypes.get(3).getValue(), 3);
        Assert.assertEquals(eTypes.get(4).getValue(), 1);
        Assert.assertEquals(eTypes.get(5).getValue(), 24);
        //Assert.assertEquals(eTypes.get(6).getValue(), -135);//FIXME
    }
}
