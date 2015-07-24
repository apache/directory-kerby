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
package org.apache.kerby.kerberos.kerb.integration.test;

import org.junit.Assert;
import org.junit.Test;

/**
 * Test login with token when token preauth is not allowed by kdc.
 */
public class TokenLoginTestWithTokenPreauthDisabled extends TokenLoginTestBase {

    @Override
    protected Boolean isTokenPreauthAllowed() {
        return false;
    }

    @Test
    public void testLoginWithTokenStr() throws Exception {
        try {
            super.testLoginWithTokenStr();
            Assert.fail("Exception should have been thrown");
        } catch (Exception e) {
          //expects exception
        }
    }

    @Test
    public void testLoginWithTokenCache() throws Exception {
        try {
            super.testLoginWithTokenCache();
            Assert.fail("Exception should have been thrown");
        } catch (Exception e) {
          //expects exception
        }
    }
}