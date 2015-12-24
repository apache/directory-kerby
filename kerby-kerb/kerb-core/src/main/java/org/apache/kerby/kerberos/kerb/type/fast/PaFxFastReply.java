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
package org.apache.kerby.kerberos.kerb.type.fast;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Choice;

/**
 PA-FX-FAST-REPLY ::= CHOICE {
    armored-data [0] KrbFastArmoredRep,
 }
 */
public class PaFxFastReply extends Asn1Choice {
    protected enum PaFxFastReplyField implements EnumType {
        ARMORED_DATA;

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
            new ExplicitField(PaFxFastReplyField.ARMORED_DATA, KrbFastArmoredRep.class)
    };

    public PaFxFastReply() {
        super(fieldInfos);
    }

    public KrbFastArmoredRep getFastArmoredRep() {
        return getChoiceValueAs(PaFxFastReplyField.ARMORED_DATA, KrbFastArmoredRep.class);
    }

    public void setFastArmoredRep(KrbFastArmoredRep fastArmoredRep) {
        setChoiceValue(PaFxFastReplyField.ARMORED_DATA, fastArmoredRep);
    }
}
