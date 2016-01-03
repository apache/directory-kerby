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
package org.apache.kerby.kerberos.kerb.type.ap;

import org.apache.kerby.asn1.type.Asn1Flags;

/**
 * The APOptions container, as defined in RFC 4120 :
 *  
 * <pre>
 * APOptions       ::= KerberosFlags
 *         -- reserved(0),
 *         -- use-session-key(1),
 *         -- mutual-required(2)
 * </pre>
 * 
 * The KerberosFlags element is defined as :
 *
 * <pre>
 * KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
 *                  -- minimum number of bits shall be sent,
 *                  -- but no fewer than 32
 * </pre>
 *
 * which defines a 32 bits length for the BIT STRING (it may be longer, but for Kerberos, it won't).
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ApOptions extends Asn1Flags {
    /**
     * Creates a default ApOptions container, with no bit set
     */
    public ApOptions() {
        this(0);
    }

    /**
     * Set the flags into the container
     * 
     * @param value The flag as an integer
     */
    public ApOptions(int value) {
        setFlags(value);
    }
}
