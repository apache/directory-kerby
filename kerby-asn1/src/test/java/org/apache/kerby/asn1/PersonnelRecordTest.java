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
package org.apache.kerby.asn1;

import org.apache.kerby.asn1.util.HexUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ref. X.690-0207(http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf),
 * Annex A, A.1 ASN.1 description of the record structure
 */
public class PersonnelRecordTest {

    static boolean verbose = false;

    @Test
    public void testEncoding() throws IOException {
        PersonnelRecord pr = DataTest.createSamplePersonnel();

        if (verbose) {
            System.out.println("Name:");
            System.out.println(HexUtil.bytesToHexFriendly(pr.getName().encode()));

            System.out.println("DateOfHire:");
            System.out.println(HexUtil.bytesToHexFriendly(pr.getDateOfHire().encode()));

            System.out.println("SpouseName:");
            System.out.println(HexUtil.bytesToHexFriendly(pr.getNameOfSpouse().encode()));

            System.out.println("Child1:");
            System.out.println(HexUtil.bytesToHexFriendly(pr.getChildren().getElements().get(0).encode()));

            System.out.println("Child2:");
            System.out.println(HexUtil.bytesToHexFriendly(pr.getChildren().getElements().get(1).encode()));

            System.out.println("Children:");
            System.out.println(HexUtil.bytesToHexFriendly(pr.getChildren().encode()));
        }

        byte[] data = DataTest.createSammplePersonnelEncodingData();
        byte[] encoded = pr.encode();

        if (verbose) {
            System.out.println("ExpectedData:");
            System.out.println(HexUtil.bytesToHexFriendly(data));

            System.out.println("Encoded:");
            System.out.println(HexUtil.bytesToHexFriendly(encoded));
        }

        assertThat(encoded).isEqualTo(data);
    }

    @Test
    public void testDecoding() throws IOException {
        PersonnelRecord expected = DataTest.createSamplePersonnel();
        byte[] data = DataTest.createSammplePersonnelEncodingData();
        Asn1.parseAndDump(data);
        PersonnelRecord decoded = new PersonnelRecord();
        decoded.decode(data);
        Asn1.dump(decoded);

        assertThat(decoded.getName().getGivenName())
                .isEqualTo(expected.getName().getGivenName());
        assertThat(decoded.getName().getInitial())
                .isEqualTo(expected.getName().getInitial());
        assertThat(decoded.getName().getFamilyName())
                .isEqualTo(expected.getName().getFamilyName());
        assertThat(decoded.getDateOfHire().getValue().getValue())
                .isEqualTo(expected.getDateOfHire().getValue().getValue());
        assertThat(decoded.getTitle())
                .isEqualTo(expected.getTitle());
        assertThat(decoded.getEmployeeNumber().getValue().getValue())
                .isEqualTo(expected.getEmployeeNumber().getValue().getValue());
        assertThat(decoded.getNameOfSpouse().getGivenName())
                .isEqualTo(expected.getNameOfSpouse().getGivenName());
        assertThat(decoded.getNameOfSpouse().getInitial())
                .isEqualTo(expected.getNameOfSpouse().getInitial());
        assertThat(decoded.getNameOfSpouse().getFamilyName())
                .isEqualTo(expected.getNameOfSpouse().getFamilyName());
        assertThat(decoded.getChildren().getElements().size())
            .isEqualTo(expected.getChildren().getElements().size());
        assertThat(decoded.getChildren().getElements().get(0).getName().getGivenName())
                .isEqualTo(expected.getChildren().getElements().get(0).getName().getGivenName());
        assertThat(decoded.getChildren().getElements().get(0).getName().getInitial())
                .isEqualTo(expected.getChildren().getElements().get(0).getName().getInitial());
        assertThat(decoded.getChildren().getElements().get(0).getName().getFamilyName())
                .isEqualTo(expected.getChildren().getElements().get(0).getName().getFamilyName());
        assertThat(decoded.getChildren().getElements().get(0).getDateOfBirth().getValue().getValue())
                .isEqualTo(expected.getChildren().getElements().get(0).getDateOfBirth().getValue().getValue());
        assertThat(decoded.getChildren().getElements().get(1).getName().getGivenName())
                .isEqualTo(expected.getChildren().getElements().get(1).getName().getGivenName());
        assertThat(decoded.getChildren().getElements().get(1).getName().getInitial())
                .isEqualTo(expected.getChildren().getElements().get(1).getName().getInitial());
        assertThat(decoded.getChildren().getElements().get(1).getName().getFamilyName())
                .isEqualTo(expected.getChildren().getElements().get(1).getName().getFamilyName());
        assertThat(decoded.getChildren().getElements().get(1).getDateOfBirth().getValue().getValue())
                .isEqualTo(expected.getChildren().getElements().get(1).getDateOfBirth().getValue().getValue());
    }
}
