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

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ad.ADAuthenticationIndicator;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataEntry;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataWrapper;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataWrapper.WrapperType;
import org.junit.Test;

/**
 * Test class for Authorization data codec.
 * 
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADTest {

    private static final String FOO = "Foo";
    private static final String BAR = "Bar";

    /**
     * Test the Authorization Data codec.
     *
     * @throws KrbException Exception
     * @throws IOException Exception
     */
    @Test
    public void testADCodec() throws KrbException, IOException {
        int i = -1;

        // Construct an AD_AUTHENTICATION_INDICATOR entry
        ADAuthenticationIndicator indicators = new ADAuthenticationIndicator();
        indicators.add(new Asn1Utf8String(FOO));
        indicators.add(new Asn1Utf8String(BAR));

        // Encode
        System.out.println("\nIndicators prior to encoding:");
        for (Asn1Utf8String ind : indicators.getAuthIndicators()) {
            System.out.println(ind.toString());
        }
        byte[] enIndicators = indicators.encode();

        // Decode get this out of asn1 tests
        indicators.decode(enIndicators);
        System.out.println("\nIndicators after decoding:");
        for (Asn1Utf8String ind : indicators.getAuthIndicators()) {
            System.out.println(ind.toString());
        }

        // Create an AD_IF_RELEVENT container
        AuthorizationData adirData = new AuthorizationData();
        adirData.add(indicators);
        AuthorizationDataWrapper adirWrap = new AuthorizationDataWrapper(WrapperType.AD_IF_RELEVANT, adirData);

        // Encode
        System.out.println("\nADE (IR) Wrapper prior to encoding:");
        for (AuthorizationDataEntry ade : adirWrap.getAuthorizationData().getElements()) {
            ADAuthenticationIndicator ad = (ADAuthenticationIndicator) ade;
            for (Asn1Utf8String ind : ad.getAuthIndicators()) {
                System.out.println(ind.toString());
            }
        }
        byte[] enAdir = adirWrap.encode();

        // Decode
        adirWrap.decode(enAdir);
        System.out.println("\nADE (IR) Wrapper after decoding:");
        for (AuthorizationDataEntry ade : adirWrap.getAuthorizationData().getElements()) {
            ADAuthenticationIndicator ad = (ADAuthenticationIndicator) ade;
            i = 0;
            for (Asn1Utf8String ind : ad.getAuthIndicators()) {
                System.out.println(ind.toString());
                if (i == 0) {
                    assertEquals(ind.getValue(), FOO);
                } else {
                    assertEquals(ind.getValue(), BAR);
                }
                i++;
            }
        }

        // Create an AD_MANDATORY_FOR_KDC container
        AuthorizationData admfkData = new AuthorizationData();
        admfkData.add(indicators);
        AuthorizationDataWrapper admfkWrap = new AuthorizationDataWrapper(WrapperType.AD_MANDATORY_FOR_KDC, admfkData);

        // Encode
        System.out.println("\nADE (MFK) Wrapper prior to encoding:");
        for (AuthorizationDataEntry ade : admfkWrap.getAuthorizationData().getElements()) {
            ADAuthenticationIndicator ad = (ADAuthenticationIndicator) ade;
            for (Asn1Utf8String ind : ad.getAuthIndicators()) {
                System.out.println(ind.toString());
            }
        }
        byte[] enAdmfk = admfkWrap.encode();

        // Decode
        admfkWrap.decode(enAdmfk);
        System.out.println("\nADE (MFK) Wrapper after decoding:");
        for (AuthorizationDataEntry ade : admfkWrap.getAuthorizationData().getElements()) {
            ADAuthenticationIndicator ad = (ADAuthenticationIndicator) ade;
            for (Asn1Utf8String ind : ad.getAuthIndicators()) {
                System.out.println(ind.toString());
            }
            i = 0;
            for (Asn1Utf8String ind : ad.getAuthIndicators()) {
                System.out.println(ind.toString());
                if (i == 0) {
                    assertEquals(ind.getValue(), FOO);
                } else {
                    assertEquals(ind.getValue(), BAR);
                }
                i++;
            }
        }
    }
}
