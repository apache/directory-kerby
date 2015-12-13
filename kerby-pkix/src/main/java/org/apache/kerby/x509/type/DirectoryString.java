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
package org.apache.kerby.x509.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1BmpString;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1PrintableString;
import org.apache.kerby.asn1.type.Asn1T61String;
import org.apache.kerby.asn1.type.Asn1UniversalString;
import org.apache.kerby.asn1.type.Asn1Utf8String;

import static org.apache.kerby.x509.type.DirectoryString.MyEnum.BMP_STRING;
import static org.apache.kerby.x509.type.DirectoryString.MyEnum.PRINTABLE_STRING;
import static org.apache.kerby.x509.type.DirectoryString.MyEnum.TELETEX_STRING;
import static org.apache.kerby.x509.type.DirectoryString.MyEnum.UNIVERSAL_STRING;
import static org.apache.kerby.x509.type.DirectoryString.MyEnum.UTF8_STRING;

/**
 * <pre>
 *  DirectoryString ::= CHOICE {
 *    teletexString               TeletexString (SIZE (1..MAX)),
 *    printableString             PrintableString (SIZE (1..MAX)),
 *    universalString             UniversalString (SIZE (1..MAX)),
 *    utf8String                  UTF8String (SIZE (1..MAX)),
 *    bmpString                   BMPString (SIZE (1..MAX))
 * }
 * </pre>
 */
public class DirectoryString extends Asn1Choice {
    protected enum MyEnum implements EnumType {
        TELETEX_STRING,
        PRINTABLE_STRING,
        UNIVERSAL_STRING,
        UTF8_STRING,
        BMP_STRING;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
            new Asn1FieldInfo(TELETEX_STRING, Asn1T61String.class),
            new Asn1FieldInfo(PRINTABLE_STRING, Asn1PrintableString.class),
            new Asn1FieldInfo(UNIVERSAL_STRING, Asn1UniversalString.class),
            new Asn1FieldInfo(UTF8_STRING, Asn1Utf8String.class),
            new Asn1FieldInfo(BMP_STRING, Asn1BmpString.class)
    };

    public DirectoryString() {
        super(fieldInfos);
    }

    public Asn1T61String getTeletexString() {
        return getChoiceValueAs(TELETEX_STRING, Asn1T61String.class);
    }

    public void setTeletexString(Asn1T61String teletexString) {
        setChoiceValue(TELETEX_STRING, teletexString);
    }

    public Asn1PrintableString getPrintableString() {
        return getChoiceValueAs(PRINTABLE_STRING, Asn1PrintableString.class);
    }

    public void setPrintableString(Asn1PrintableString printableString) {
        setChoiceValue(PRINTABLE_STRING, printableString);
    }

    public Asn1UniversalString getUniversalString() {
        return getChoiceValueAs(UNIVERSAL_STRING, Asn1UniversalString.class);
    }

    public void setUniversalString(Asn1UniversalString universalString) {
        setChoiceValue(UNIVERSAL_STRING, universalString);
    }

    public Asn1Utf8String getUtf8String() {
        return getChoiceValueAs(UTF8_STRING, Asn1Utf8String.class);
    }

    public void setUtf8String(Asn1Utf8String utf8String) {
        setChoiceValue(UTF8_STRING, utf8String);
    }

    public Asn1BmpString getBmpString() {
        return getChoiceValueAs(BMP_STRING, Asn1BmpString.class);
    }

    public void setBmpString(Asn1BmpString bmpString) {
        setChoiceValue(BMP_STRING, bmpString);
    }
}
