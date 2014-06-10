package org.haox.asn1;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

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

        Assert.assertArrayEquals(data, encoded);
    }

    @Test
    public void testDecoding() throws IOException {
        PersonnelRecord expected = TestData.createSamplePersonnel();
        byte[] data = TestData.createSammplePersonnelEncodingData();
        PersonnelRecord decoded = new PersonnelRecord();
        decoded.decode(data);

        Assert.assertEquals(expected.getName().getGivenName(),
                decoded.getName().getGivenName());
        Assert.assertEquals(expected.getName().getInitial(),
                decoded.getName().getInitial());
        Assert.assertEquals(expected.getName().getFamilyName(),
                decoded.getName().getFamilyName());

        Assert.assertEquals(expected.getDateOfHire().getValue().getValue(),
                decoded.getDateOfHire().getValue().getValue());
        Assert.assertEquals(expected.getTitle(), decoded.getTitle());
        Assert.assertEquals(expected.getEmployeeNumber().getValue().getValue(),
                decoded.getEmployeeNumber().getValue().getValue());

        Assert.assertEquals(expected.getNameOfSpouse().getGivenName(),
                decoded.getNameOfSpouse().getGivenName());
        Assert.assertEquals(expected.getNameOfSpouse().getInitial(),
                decoded.getNameOfSpouse().getInitial());
        Assert.assertEquals(expected.getNameOfSpouse().getFamilyName(),
                decoded.getNameOfSpouse().getFamilyName());

        Assert.assertEquals(expected.getChildren().getElements().get(0).getName().getGivenName(),
                decoded.getChildren().getElements().get(0).getName().getGivenName());
        Assert.assertEquals(expected.getChildren().getElements().get(0).getName().getInitial(),
                decoded.getChildren().getElements().get(0).getName().getInitial());
        Assert.assertEquals(expected.getChildren().getElements().get(0).getName().getFamilyName(),
                decoded.getChildren().getElements().get(0).getName().getFamilyName());
        Assert.assertEquals(expected.getChildren().getElements().get(0).getDateOfBirth().getValue().getValue(),
                decoded.getChildren().getElements().get(0).getDateOfBirth().getValue().getValue());

        Assert.assertEquals(expected.getChildren().getElements().get(1).getName().getGivenName(),
                decoded.getChildren().getElements().get(1).getName().getGivenName());
        Assert.assertEquals(expected.getChildren().getElements().get(1).getName().getInitial(),
                decoded.getChildren().getElements().get(1).getName().getInitial());
        Assert.assertEquals(expected.getChildren().getElements().get(1).getName().getFamilyName(),
                decoded.getChildren().getElements().get(1).getName().getFamilyName());
        Assert.assertEquals(expected.getChildren().getElements().get(1).getDateOfBirth().getValue().getValue(),
                decoded.getChildren().getElements().get(1).getDateOfBirth().getValue().getValue());
    }
}
