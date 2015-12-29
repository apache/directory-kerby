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
import org.apache.kerby.asn1.type.Asn1Boolean;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import java.math.BigInteger;

/**
 * <pre>
 * BasicConstraints := SEQUENCE {
 *    cA                  BOOLEAN DEFAULT FALSE,
 *    pathLenConstraint   INTEGER (0..MAX) OPTIONAL
 * }
 * </pre>
 */
public class BasicConstraints extends Asn1SequenceType {
    protected enum BasicConstraintsField implements EnumType {
        CA,
        PATH_LEN_CONSTRAINT;

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
        new Asn1FieldInfo(BasicConstraintsField.CA, Asn1Boolean.class),
        new Asn1FieldInfo(BasicConstraintsField.PATH_LEN_CONSTRAINT, Asn1Integer.class)
    };

    public BasicConstraints() {
        super(fieldInfos);
    }

    public boolean isCA() {
        return false;
    }

    public boolean getCA() {
        return getFieldAs(BasicConstraintsField.CA, Asn1Boolean.class).getValue();
    }

    public void setCA(Asn1Boolean isCA) {
        setFieldAs(BasicConstraintsField.CA, isCA);
    }

    public BigInteger getPathLenConstraint() {
        return getFieldAs(BasicConstraintsField.PATH_LEN_CONSTRAINT, Asn1Integer.class).getValue();
    }

    public void setPathLenConstraint(Asn1Integer pathLenConstraint) {
        setFieldAs(BasicConstraintsField.PATH_LEN_CONSTRAINT, pathLenConstraint);
    }
}
