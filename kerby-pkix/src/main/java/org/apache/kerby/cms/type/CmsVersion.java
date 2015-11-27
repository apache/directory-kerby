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

import org.apache.kerby.asn1.type.Asn1EnumType;
import org.apache.kerby.asn1.type.Asn1Integer;

/**
 * CMSVersion ::= INTEGER
 * { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
 */

enum CmsVersionEnum implements Asn1EnumType {
    V0,
    V1,
    V2,
    V3,
    V4,
    V5;

    @Override
    public int getValue() {
        return ordinal();
    }
}

public class CmsVersion extends Asn1Integer {

    public CmsVersion() {
        this(CmsVersionEnum.V0);
    }

    public CmsVersion(CmsVersionEnum version) {
        super(version.getValue());
    }
}
