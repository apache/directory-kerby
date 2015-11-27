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
package org.apache.kerby.asn1.type;

/**
 * Representing an explicitly tagged field in a ASN1 collection or choice.
 */
public class ExplicitField extends Asn1FieldInfo {

    /**
     * Constructor for an explicitly tagged field.
     * @param index
     * @param type
     */
    public ExplicitField(int index, int tagNo, Class<? extends Asn1Type> type) {
        super(index, tagNo, type, false);
    }

    /**
     * Constructor for an explicitly tagged field, the tagNo being the same of index.
     * @param index
     * @param type
     */
    public ExplicitField(int index, Class<? extends Asn1Type> type) {
        super(index, index, type, false);
    }
}
