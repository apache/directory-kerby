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

import org.apache.kerby.asn1.Asn1;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.cms.type.ContentInfo;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.DHRepInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsRep;
import org.junit.Test;

import java.io.IOException;

public class TestPaPkAsRep {

    @Test
    public void test() throws IOException, KrbException {
        PaPkAsRep paPkAsRep = new PaPkAsRep();
        DHRepInfo dhRepInfo = new DHRepInfo();
        ContentInfo contentInfo = new ContentInfo();
        contentInfo.setContentType(new Asn1ObjectIdentifier("1.2.840.113549.1.7.2"));
        dhRepInfo.setDHSignedData(contentInfo.encode());
        paPkAsRep.setDHRepInfo(dhRepInfo);
        Asn1.parseAndDump(paPkAsRep.encode());
        //TO BE FIXED
        //KrbCodec.decode(paPkAsRep.encode(), PaPkAsRep.class);
    }
}
