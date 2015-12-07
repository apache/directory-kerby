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

import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceOf;
import org.apache.kerby.asn1.type.Asn1SetType;
import org.apache.kerby.asn1.type.Asn1Tagging;
import org.apache.kerby.asn1.type.Asn1TaggingSequence;
import org.apache.kerby.asn1.type.Asn1TaggingSet;
import org.apache.kerby.asn1.type.Asn1VisibleString;

import static org.apache.kerby.asn1.PersonnelRecord.ChildInformation.MyEnum.CHILD_NAME;
import static org.apache.kerby.asn1.PersonnelRecord.ChildInformation.MyEnum.DATEOFBIRTH;
import static org.apache.kerby.asn1.PersonnelRecord.MyEnum.CHILDREN;
import static org.apache.kerby.asn1.PersonnelRecord.MyEnum.DATEOFHIRE;
import static org.apache.kerby.asn1.PersonnelRecord.MyEnum.NAME;
import static org.apache.kerby.asn1.PersonnelRecord.MyEnum.NAMEOFSPOUSE;
import static org.apache.kerby.asn1.PersonnelRecord.MyEnum.NUMBER;
import static org.apache.kerby.asn1.PersonnelRecord.MyEnum.TITLE;
import static org.apache.kerby.asn1.PersonnelRecord.Name.MyEnum.FAMILYNAME;
import static org.apache.kerby.asn1.PersonnelRecord.Name.MyEnum.GIVENNAME;
import static org.apache.kerby.asn1.PersonnelRecord.Name.MyEnum.INITIAL;

/**
 * Ref. X.690-0207(http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf),
 * Annex A, A.1 ASN.1 description of the record structure
 */
public class PersonnelRecord extends Asn1TaggingSet {
    protected static enum MyEnum implements EnumType {
        NAME,
        TITLE,
        NUMBER,
        DATEOFHIRE,
        NAMEOFSPOUSE,
        CHILDREN;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(NAME, -1, Name.class),
            new ExplicitField(TITLE, 0, Asn1VisibleString.class),
            new ExplicitField(NUMBER, -1, EmployeeNumber.class),
            new ExplicitField(DATEOFHIRE, 1, Date.class),
            new ExplicitField(NAMEOFSPOUSE, 2, Name.class),
            new ImplicitField(CHILDREN, 3, Children.class)
    };

    public PersonnelRecord() {
        super(0, fieldInfos, true, true);
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
        public Children(ChildInformation ... children) {
            super();
            for (ChildInformation child : children) {
                addElement(child);
            }
        }

        public Children() {
            super();
        }
    }

    public static class ChildInformation extends Asn1SetType {
        protected static enum MyEnum implements EnumType {
            CHILD_NAME,
            DATEOFBIRTH;

            @Override
            public int getValue() {
                return ordinal();
            }

            @Override
            public String getName() {
                return name();
            }
        }

        static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
                new ExplicitField(CHILD_NAME, -1, Name.class),
                new ExplicitField(DATEOFBIRTH, 0, Date.class)
        };

        public ChildInformation() {
            super(tags);
        }

        public void setName(Name name) {
            setFieldAs(CHILD_NAME, name);
        }

        public Name getName() {
            return getFieldAs(CHILD_NAME, Name.class);
        }

        public void setDateOfBirth(Date date) {
            setFieldAs(DATEOFBIRTH, date);
        }

        public Date getDateOfBirth() {
            return getFieldAs(DATEOFBIRTH, Date.class);
        }
    }

    public static class Name extends Asn1TaggingSequence {

        protected static enum MyEnum implements EnumType {
            GIVENNAME,
            INITIAL,
            FAMILYNAME;

            @Override
            public int getValue() {
                return ordinal();
            }

            @Override
            public String getName() {
                return name();
            }
        }

        static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
                new ExplicitField(GIVENNAME, -1, Asn1VisibleString.class),
                new ExplicitField(INITIAL, -1, Asn1VisibleString.class),
                new ExplicitField(FAMILYNAME, -1, Asn1VisibleString.class)
        };

        public Name() {
            super(1, tags, true, true);
        }

        public Name(String givenName, String initial, String familyName) {
            this();
            setGivenName(givenName);
            setInitial(initial);
            setFamilyName(familyName);
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
        public EmployeeNumber(Integer value) {
            super(2, new Asn1Integer(value), true, true);
        }

        public EmployeeNumber() {
            super(2, new Asn1Integer(), true, true);
        }
    }

    public static class Date extends Asn1Tagging<Asn1VisibleString> {
        public Date(String value) {
            super(3, new Asn1VisibleString(value), true, true);
        }
        public Date() {
            this(null);
        }
    }
}