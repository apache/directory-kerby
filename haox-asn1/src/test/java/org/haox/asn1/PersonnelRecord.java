package org.haox.asn1;

import org.haox.asn1.type.*;

public class PersonnelRecord extends TaggingSet {
    private static int NAME = 0;
    private static int TITLE = 1;
    private static int NUMBER = 2;
    private static int DATEOFHIRE= 3;
    private static int NAMEOFSPOUSE = 4;
    private static int CHILDREN = 5;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(NAME, -1, Name.class),
            new Asn1FieldInfo(TITLE, 0, Asn1VisibleString.class),
            new Asn1FieldInfo(NUMBER, 1, EmployeeNumber.class),
            new Asn1FieldInfo(DATEOFHIRE, 2, Date.class),
            new Asn1FieldInfo(NAMEOFSPOUSE, 3, Name.class),
            new Asn1FieldInfo(CHILDREN, -1, Children.class)
    };

    public PersonnelRecord() {
        super(0, fieldInfos, true);
        setEncodingOption(EncodingOption.IMPLICIT);
    }

    public void setName(Name name) {
        setFieldAs(NAME, name);
    }

    public Name getName() {
        return getFieldAs(NAME, Name.class);
    }

    public void setTitle(String title) {
        setFieldAs(TITLE, new Asn1VisibleString(title));
    }

    public String getTitle() {
        return getFieldAsString(TITLE);
    }

    public void setEmployeeNumber(EmployeeNumber employeeNumber) {
        setFieldAs(NUMBER, employeeNumber);
    }

    public EmployeeNumber getEmployeeNumber() {
        return getFieldAs(NUMBER, EmployeeNumber.class);
    }

    public void setDateOfHire(Date dateOfHire) {
        setFieldAs(DATEOFHIRE, dateOfHire);
    }

    public Date getDateOfHire() {
        return getFieldAs(DATEOFHIRE, Date.class);
    }

    public void setNameOfSpouse(Name spouse) {
        setFieldAs(NAMEOFSPOUSE, spouse);
    }

    public Name getNameOfSpouse() {
        return getFieldAs(NAMEOFSPOUSE, Name.class);
    }

    public void setChildren(Children children) {
        setFieldAs(CHILDREN, children);
    }

    public Children getChildren() {
        return getFieldAs(CHILDREN, Children.class);
    }

    public static class Children extends Asn1SequenceOf<ChildInformation> {

    }

    public static class ChildInformation extends Asn1SetType {
        private static int NAME = 0;
        private static int DATEOFBIRTH = 1;

        static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
                new Asn1FieldInfo(NAME, -1, Name.class),
                new Asn1FieldInfo(DATEOFBIRTH, 0, Date.class)
        };

        public ChildInformation() {
            super(tags);
        }

        public void setName(String name) {
            setFieldAs(NAME, new Asn1VisibleString(name));
        }

        public String getName() {
            return getFieldAsString(NAME);
        }

        public void setDate(Date date) {
            setFieldAs(DATEOFBIRTH, date);
        }

        public Date getDate() {
            return getFieldAs(NAME, Date.class);
        }
    }

    public static class Name extends TaggingSequence {
        private static int GIVENNAME = 0;
        private static int INITIAL = 1;
        private static int FAMILYNAME = 2;

        static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
                new Asn1FieldInfo(GIVENNAME, -1, Asn1VisibleString.class),
                new Asn1FieldInfo(INITIAL, -1, Asn1VisibleString.class),
                new Asn1FieldInfo(FAMILYNAME, -1, Asn1VisibleString.class)
        };

        public Name() {
            super(1, tags, true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }

        public void setGivenName(String givenName) {
            setFieldAs(GIVENNAME, new Asn1VisibleString(givenName));
        }

        public String getGivenName() {
            return getFieldAsString(GIVENNAME);
        }

        public void setInitial(String initial) {
            setFieldAs(INITIAL, new Asn1VisibleString(initial));
        }

        public String getInitial() {
            return getFieldAsString(INITIAL);
        }

        public void setFamilyName(String familyName) {
            setFieldAs(FAMILYNAME, new Asn1VisibleString(familyName));
        }

        public String getFamilyName() {
            return getFieldAsString(FAMILYNAME);
        }
    }

    public static class EmployeeNumber extends Asn1Tagging<Asn1Integer> {
        public EmployeeNumber(Asn1Integer value) {
            super(2, value, true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }
        public EmployeeNumber() {
            this(null);
        }
    }

    public static class Date extends Asn1Tagging<Asn1VisibleString> {
        public Date(Asn1VisibleString value) {
            super(3, value, true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }
        public Date() {
            this(null);
        }
    }
}