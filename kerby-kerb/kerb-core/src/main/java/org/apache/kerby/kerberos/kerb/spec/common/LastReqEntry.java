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
package org.apache.kerby.kerberos.kerb.spec.common;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReqEntry extends KrbSequenceType {
    private static int LR_TYPE = 0;
    private static int LR_VALUE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(LR_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(LR_VALUE, 1, KerberosTime.class)
    };

    public LastReqEntry() {
        super(fieldInfos);
    }

    public LastReqType getLrType() {
        Integer value = getFieldAsInteger(LR_TYPE);
        return LastReqType.fromValue(value);
    }

    public void setLrType(LastReqType lrType) {
        setFieldAsInt(LR_TYPE, lrType.getValue());
    }

    public KerberosTime getLrValue() {
        return getFieldAs(LR_VALUE, KerberosTime.class);
    }

    public void setLrValue(KerberosTime lrValue) {
        setFieldAs(LR_VALUE, lrValue);
    }
}
