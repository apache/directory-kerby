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
package org.apache.kerby.kerberos.kerb.crypto.dh;

import org.junit.Test;

/**
 * "When using the Diffie-Hellman key agreement method, implementations MUST
 * support Oakley 1024-bit Modular Exponential (MODP) well-known group 2
 * [RFC2412] and Oakley 2048-bit MODP well-known group 14 [RFC3526] and
 * SHOULD support Oakley 4096-bit MODP well-known group 16 [RFC3526]."
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class DhGroupTest extends org.junit.Assert {
    /**
     * Tests that the translation of the hex representation of the prime modulus
     * resulted in the expected bit length.
     */
    @Test
    public void testPrimeBitLengths() {
        assertEquals(1024, DhGroup.MODP_GROUP2.getP().bitLength());
        assertEquals(2048, DhGroup.MODP_GROUP14.getP().bitLength());
        assertEquals(4096, DhGroup.MODP_GROUP16.getP().bitLength());
    }

    /**
     * Tests the generator values.
     */
    @Test
    public void testGeneratorValues() {
        assertEquals(2, DhGroup.MODP_GROUP2.getG().intValue());
        assertEquals(2, DhGroup.MODP_GROUP14.getG().intValue());
        assertEquals(2, DhGroup.MODP_GROUP16.getG().intValue());
    }
}
