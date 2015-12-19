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
package org.apache.kerby.cms.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1Choice;

import static org.apache.kerby.cms.type.RecipientInfo.MyEnum.*;

/**
 * RecipientInfo ::= CHOICE {
 *   ktri KeyTransRecipientInfo,
 *   kari [1] KeyAgreeRecipientInfo,
 *   kekri [2] KEKRecipientInfo,
 *   pwri [3] PasswordRecipientInfo,
 *   ori [4] OtherRecipientInfo }
 */
public class RecipientInfo extends Asn1Choice {
    protected enum MyEnum implements EnumType {
        KTRI,
        KARI,
        KEKRI,
        PWRI,
        ORI;

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
            new Asn1FieldInfo(KTRI, KeyTransRecipientInfo.class),
            new ImplicitField(KARI, 1, KeyAgreeRecipientInfo.class),
            new ImplicitField(KEKRI, 2, KEKRecipientInfo.class),
            new ImplicitField(PWRI, 3, PasswordRecipientInfo.class),
            new ImplicitField(ORI, 4, OtherRecipientInfo.class)
    };

    public RecipientInfo() {
        super(fieldInfos);
    }

    public KeyTransRecipientInfo getKtri() {
        return getChoiceValueAs(KTRI, KeyTransRecipientInfo.class);
    }

    public void setKtri(KeyTransRecipientInfo ktri) {
        setChoiceValue(KTRI, ktri);
    }

    public KeyAgreeRecipientInfo getKari() {
        return getChoiceValueAs(KARI, KeyAgreeRecipientInfo.class);
    }

    public void setKari(KeyAgreeRecipientInfo kari) {
        setChoiceValue(KARI, kari);
    }

    public KEKRecipientInfo getKekri() {
        return getChoiceValueAs(KEKRI, KEKRecipientInfo.class);
    }

    public void setKekri(KEKRecipientInfo kekri) {
        setChoiceValue(KEKRI, kekri);
    }

    public PasswordRecipientInfo getPwri() {
        return getChoiceValueAs(PWRI, PasswordRecipientInfo.class);
    }

    public void setPwri(PasswordRecipientInfo pwri) {
        setChoiceValue(PWRI, pwri);
    }

    public OtherRecipientInfo getori() {
        return getChoiceValueAs(ORI, OtherRecipientInfo.class);
    }

    public void setOri(OtherRecipientInfo ori) {
        setChoiceValue(ORI, ori);
    }
}
