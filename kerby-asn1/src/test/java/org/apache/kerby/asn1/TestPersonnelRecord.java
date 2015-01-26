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

import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ref. X.690-0207(http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf),
 * Annex A, A.1 ASN.1 description of the record structure
 */
public class TestPersonnelRecord {

    static boolean verbose = false;

    @Test
    public void testEncoding() {
        PersonnelRecord pr = TestData.createSamplePersonnel();

        if (verbose) {
            System.out.println("Name:");
            System.out.println(Util.bytesToHex(pr.getName().encode()));

        /*
        System.out.println("Title:");
        System.out.println(Util.bytesToHex(pr.getFieldAs(1, Asn1VisibleString.class).encode()));

        System.out.println("EmployeeNumber:");
        System.out.println(Util.bytesToHex(pr.getFieldAs(2, EmployeeNumber.class).encode()));
        */

            System.out.println("DateOfHire:");
            System.out.println(Util.bytesToHex(pr.getDateOfHire().encode()));

            System.out.println("SpouseName:");
            System.out.println(Util.bytesToHex(pr.getNameOfSpouse().encode()));

            System.out.println("Child1:");
            System.out.println(Util.bytesToHex(pr.getChildren().getElements().get(0).encode()));

            System.out.println("Child2:");
            System.out.println(Util.bytesToHex(pr.getChildren().getElements().get(1).encode()));

            System.out.println("Children:");
            System.out.println(Util.bytesToHex(pr.getChildren().encode()));
        }

        byte[] data = TestData.createSammplePersonnelEncodingData();
        byte[] encoded = pr.encode();

        if (verbose) {
            System.out.println("ExpectedData:");
            System.out.println(Util.bytesToHex(data));

            System.out.println("Encoded:");
            System.out.println(Util.bytesToHex(encoded));
        }

        assertThat(encoded).isEqualTo(data);
    }

    @Test
    public void testDecoding() throws IOException {
        PersonnelRecord expected = TestData.createSamplePersonnel();
        byte[] data = TestData.createSammplePersonnelEncodingData();
        PersonnelRecord decoded = new PersonnelRecord();
        decoded.decode(data);

        assertThat(expected.getName().getGivenName())
                .isEqualTo(decoded.getName().getGivenName());
        assertThat(expected.getName().getInitial())
                .isEqualTo(decoded.getName().getInitial());
        assertThat(expected.getName().getFamilyName())
                .isEqualTo(decoded.getName().getFamilyName());
        assertThat(expected.getDateOfHire().getValue().getValue())
                .isEqualTo(decoded.getDateOfHire().getValue().getValue());
        assertThat(decoded.getTitle())
                .isEqualTo(expected.getTitle());
        assertThat(expected.getEmployeeNumber().getValue().getValue())
                .isEqualTo(decoded.getEmployeeNumber().getValue().getValue());
        assertThat(expected.getNameOfSpouse().getGivenName())
                .isEqualTo(decoded.getNameOfSpouse().getGivenName());
        assertThat(expected.getNameOfSpouse().getInitial())
                .isEqualTo(decoded.getNameOfSpouse().getInitial());
        assertThat(expected.getNameOfSpouse().getFamilyName())
                .isEqualTo(decoded.getNameOfSpouse().getFamilyName());
        assertThat(expected.getChildren().getElements().get(0).getName().getGivenName())
                .isEqualTo(decoded.getChildren().getElements().get(0).getName().getGivenName());
        assertThat(expected.getChildren().getElements().get(0).getName().getInitial())
                .isEqualTo(decoded.getChildren().getElements().get(0).getName().getInitial());
        assertThat(expected.getChildren().getElements().get(0).getName().getFamilyName())
                .isEqualTo(decoded.getChildren().getElements().get(0).getName().getFamilyName());
        assertThat(expected.getChildren().getElements().get(0).getDateOfBirth().getValue().getValue())
                .isEqualTo(decoded.getChildren().getElements().get(0).getDateOfBirth().getValue().getValue());
        assertThat(expected.getChildren().getElements().get(1).getName().getGivenName())
                .isEqualTo(decoded.getChildren().getElements().get(1).getName().getGivenName());
        assertThat(expected.getChildren().getElements().get(1).getName().getInitial())
                .isEqualTo(decoded.getChildren().getElements().get(1).getName().getInitial());
        assertThat(expected.getChildren().getElements().get(1).getName().getFamilyName())
                .isEqualTo(decoded.getChildren().getElements().get(1).getName().getFamilyName());
        assertThat(expected.getChildren().getElements().get(1).getDateOfBirth().getValue().getValue())
                .isEqualTo(decoded.getChildren().getElements().get(1).getDateOfBirth().getValue().getValue());
    }
}
