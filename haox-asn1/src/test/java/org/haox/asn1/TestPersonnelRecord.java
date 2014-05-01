package org.haox.asn1;

import org.haox.asn1.PersonnelRecord.*;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class TestPersonnelRecord {

    static boolean verbose = false;

    static PersonnelRecord createSamplePersonnel() {
        PersonnelRecord pr = new PersonnelRecord();

        pr.setName(new Name("John", "P", "Smith"));

        pr.setTitle("Director");

        pr.setEmployeeNumber(new EmployeeNumber(51));

        pr.setDateOfHire(new Date("19710917"));

        pr.setNameOfSpouse(new Name("Mary", "T", "Smith"));

        ChildInformation child1 = new ChildInformation();
        child1.setName(new Name("Ralph", "T", "Smith"));
        child1.setDateOfBirth(new Date("19571111"));

        ChildInformation child2 = new ChildInformation();
        child2.setName(new Name("Susan", "B", "Jones"));
        child2.setDateOfBirth(new Date("19590717"));

        pr.setChildren(new Children(child1, child2));

        return pr;
    }

    static byte[] createSammpleEncodingData() {
        class BufferOutput {
            ByteBuffer buffer;

            void put(byte ... bytes) {
                buffer.put(bytes);
            }

            void put(String s) {
                byte[] bytes = s.getBytes(StandardCharsets.US_ASCII);
                buffer.put(bytes);
            }

            public byte[] output() {
                int len = (int) 0x85 + 3;
                buffer = ByteBuffer.allocate(len);

                // personnel record
                put((byte) 0x60, (byte) 0x81, (byte) 0x85);

                // -name
                put((byte) 0x61, (byte) 0x10);
                put((byte) 0x1A, (byte) 0x04); put("John");
                put((byte) 0x1A, (byte) 0x01); put("P");
                put((byte) 0x1A, (byte) 0x05); put("Smith");

                //-title
                put((byte) 0xA0, (byte) 0x0A);
                put((byte) 0x1A, (byte) 0x08); put("Director");

                //-employee number
                put((byte) 0x42, (byte) 0x01, (byte) 0x33);

                //-date of hire
                put((byte) 0xA1, (byte) 0x0A);
                put((byte) 0x43, (byte) 0x08); put("19710917");

                //-spouse
                put((byte) 0xA2, (byte) 0x12);
                put((byte) 0x61, (byte) 0x10);
                put((byte) 0x1A, (byte) 0x04); put("Mary");
                put((byte) 0x1A, (byte) 0x01); put("T");
                put((byte) 0x1A, (byte) 0x05); put("Smith");

                //-children
                put((byte) 0xA3, (byte) 0x42);
                //--child 1
                put((byte) 0x31, (byte) 0x1F);
                //---name
                put((byte) 0x61, (byte) 0x11);
                put((byte) 0x1A, (byte) 0x05); put("Ralph");
                put((byte) 0x1A, (byte) 0x01); put("T");
                put((byte) 0x1A, (byte) 0x05); put("Smith");
                //-date of birth
                put((byte) 0xA0, (byte) 0x0A);
                put((byte) 0x43, (byte) 0x08); put("19571111");
                //--child 2
                put((byte) 0x31, (byte) 0x1F);
                //---name
                put((byte) 0x61, (byte) 0x11);
                put((byte) 0x1A, (byte) 0x05); put("Susan");
                put((byte) 0x1A, (byte) 0x01); put("B");
                put((byte) 0x1A, (byte) 0x05); put("Jones");
                //-date of birth
                put((byte) 0xA0, (byte) 0x0A);
                put((byte) 0x43, (byte) 0x08); put("19590717");

                return buffer.array();
            }
        }

        BufferOutput buffer = new BufferOutput();
        return buffer.output();
    }

    @Test
    public void testEncoding() {
        PersonnelRecord pr = createSamplePersonnel();

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

        byte[] data = createSammpleEncodingData();
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
        PersonnelRecord expected = createSamplePersonnel();
        byte[] data = createSammpleEncodingData();
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
