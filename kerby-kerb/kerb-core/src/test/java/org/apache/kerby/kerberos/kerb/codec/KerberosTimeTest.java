/*
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
package org.apache.kerby.kerberos.kerb.codec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.junit.Test;

/**
 * Testing the KerberosTime class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class KerberosTimeTest {
    @Test
    public void testLessThan() {
        KerberosTime kerberosTime = new KerberosTime();
        
        assertTrue(kerberosTime.lessThan(System.currentTimeMillis() + 100));
        assertFalse(kerberosTime.lessThan(System.currentTimeMillis() - 10000));
    }
    
    
    @Test
    public void testGreaterThan() {
        KerberosTime kerberosTime = new KerberosTime();
        
        assertTrue(kerberosTime.greaterThan(new KerberosTime(System.currentTimeMillis() - 10000)));
        assertFalse(kerberosTime.greaterThan(new KerberosTime(System.currentTimeMillis() + 100)));
    }
    
    
    @Test
    public void testExtend() {
        KerberosTime kerberosTime = new KerberosTime();
        
        KerberosTime extended = kerberosTime.extend(1000);
        
        assertTrue(kerberosTime.lessThan(extended));
        assertFalse(kerberosTime.greaterThan(extended));
        
        assertEquals(-1000L, kerberosTime.diff(extended));
    }
}
