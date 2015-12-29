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
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import java.math.BigInteger;

public class DSAParameter extends Asn1SequenceType {
    protected enum DSAParameterField implements EnumType {
        P,
        Q,
        G;

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
        new Asn1FieldInfo(DSAParameterField.P, Asn1Integer.class),
        new Asn1FieldInfo(DSAParameterField.Q, Asn1Integer.class),
        new Asn1FieldInfo(DSAParameterField.G, Asn1Integer.class)
    };

    public DSAParameter() {
        super(fieldInfos);
    }

    public BigInteger getP() {
        return getFieldAs(DSAParameterField.P, Asn1Integer.class).getValue();
    }

    public void setP(BigInteger p) {
        setFieldAs(DSAParameterField.P, new Asn1Integer(p));
    }

    public BigInteger getQ() {
        return getFieldAs(DSAParameterField.Q, Asn1Integer.class).getValue();
    }

    public void setQ(BigInteger q) {
        setFieldAs(DSAParameterField.Q, new Asn1Integer(q));
    }

    public BigInteger getG() {
        return getFieldAs(DSAParameterField.G, Asn1Integer.class).getValue();
    }

    public void setG(BigInteger g) {
        setFieldAs(DSAParameterField.G, new Asn1Integer(g));
    }
}
