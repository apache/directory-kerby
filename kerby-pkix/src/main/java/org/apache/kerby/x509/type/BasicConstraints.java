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

import org.apache.kerby.asn1.type.Asn1Boolean;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
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
    private static final int CA = 0;
    private static final int PATH_LEN_CONSTRAINT = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(CA, Asn1Boolean.class),
        new Asn1FieldInfo(PATH_LEN_CONSTRAINT, Asn1Integer.class)
    };

    public BasicConstraints() {
        super(fieldInfos);
    }

    public boolean isCA() {
        return false;
    }

    public boolean getCA() {
        return getFieldAs(CA, Asn1Boolean.class).getValue();
    }

    public void setCA(Asn1Boolean isCA) {
        setFieldAs(CA, isCA);
    }

    public BigInteger getPathLenConstraint() {
        return getFieldAs(PATH_LEN_CONSTRAINT, Asn1Integer.class).getValue();
    }

    public void setPathLenConstraint(Asn1Integer pathLenConstraint) {
        setFieldAs(PATH_LEN_CONSTRAINT, pathLenConstraint);
    }
}
