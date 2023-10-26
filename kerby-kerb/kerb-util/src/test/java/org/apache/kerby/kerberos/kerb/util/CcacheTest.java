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
package org.apache.kerby.kerberos.kerb.util;

import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;

/*
Default principal: drankye@SH.INTEL.COM

Valid starting       Expires              Service principal
08/05/2014 00:13:17  08/05/2014 10:13:17  krbtgt/SH.INTEL.COM@SH.INTEL.COM
        Flags: FIA, Etype (skey, tkt): des3-cbc-sha1, des3-cbc-sha1
 */
public class CcacheTest {

    private CredentialCache cc;

    @BeforeEach
    public void setUp() throws IOException {
        try (InputStream cis = CcacheTest.class.getResourceAsStream("/test.cc")) {
            cc = new CredentialCache();
            cc.load(cis);
        }
    }

    @Test
    public void testCc() {
        assertThat(cc).isNotNull();

        PrincipalName princ = cc.getPrimaryPrincipal();
        assertThat(princ).isNotNull();
        assertThat(princ.getName().equals("drankye@SH.INTEL.COM")).isTrue();
    }
}
