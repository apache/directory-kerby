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
package org.apache.kerby.kerberos.kerb.type.base;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReqEntry extends KrbSequenceType {
    protected enum LastReqEntryField implements EnumType {
        LR_TYPE,
        LR_VALUE;

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
            new ExplicitField(LastReqEntryField.LR_TYPE, Asn1Integer.class),
            new ExplicitField(LastReqEntryField.LR_VALUE, KerberosTime.class)
    };

    public LastReqEntry() {
        super(fieldInfos);
    }

    public LastReqType getLrType() {
        Integer value = getFieldAsInteger(LastReqEntryField.LR_TYPE);
        return LastReqType.fromValue(value);
    }

    public void setLrType(LastReqType lrType) {
        setFieldAsInt(LastReqEntryField.LR_TYPE, lrType.getValue());
    }

    public KerberosTime getLrValue() {
        return getFieldAs(LastReqEntryField.LR_VALUE, KerberosTime.class);
    }

    public void setLrValue(KerberosTime lrValue) {
        setFieldAs(LastReqEntryField.LR_VALUE, lrValue);
    }
}
