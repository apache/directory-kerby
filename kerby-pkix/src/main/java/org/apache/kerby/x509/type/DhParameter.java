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

public class DhParameter extends Asn1SequenceType {
    protected enum DhParameterField implements EnumType {
        P,
        G,
        Q;

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
            new Asn1FieldInfo(DhParameterField.P, Asn1Integer.class),
            new Asn1FieldInfo(DhParameterField.G, Asn1Integer.class),
            new Asn1FieldInfo(DhParameterField.Q, Asn1Integer.class),
    };

    public DhParameter() {
        super(fieldInfos);
    }

    public void setP(BigInteger p) {
        setFieldAsInt(DhParameterField.P, p);
    }

    public BigInteger getP() {
        Asn1Integer p = getFieldAs(DhParameterField.P, Asn1Integer.class);
        return p.getValue();
    }

    public void setG(BigInteger g) {
        setFieldAsInt(DhParameterField.G, g);
    }

    public BigInteger getG() {
        Asn1Integer g = getFieldAs(DhParameterField.G, Asn1Integer.class);
        return g.getValue();
    }

    public void setQ(BigInteger q) {
        setFieldAsInt(DhParameterField.Q, q);
    }

    public BigInteger getQ() {
        Asn1Integer q = getFieldAs(DhParameterField.Q, Asn1Integer.class);
        return q.getValue();
    }
}
