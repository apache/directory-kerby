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
package org.apache.kerby.kerberos.kerb.type;

import org.apache.kerby.asn1.type.Asn1GeneralString;

/**
 * The Kerberos String, as defined in RFC 4120. It restricts the set of chars that
 * can be used to [0x00..0x7F]
 * 
 * KerberosString  ::= GeneralString -- (IA5String)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class KerberosString extends Asn1GeneralString {
    /**
     * Creates a new KerberosString
     */
    public KerberosString() {
        super();
    }

    /**
     * Creates a new KerberosString with an initial value
     * 
     * @param value The String to store in teh KerberosString
     */
    public KerberosString(String value) {
        super(value);
    }
}
