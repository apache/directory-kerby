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
package org.apache.haox.config;

import org.junit.Assert;
import org.junit.Test;

/**
 * The test is on ConfigImpl level.
 * ConfigImpl is the internal implementation of Conf, only visual by developers.
 */
public class ConfigImplTest {

    /**
     * Test for section config support.
     */
    @Test
    public void testSectionConfig() {
        ConfigImpl rootConfig = new ConfigImpl(null);
        rootConfig.set("globalConfig", "true");

        ConfigImpl sectionA = new ConfigImpl("libdefaults");
        rootConfig.set("libdefaults", sectionA);
        sectionA.set("default_realm", "EXAMPLE.COM");
        sectionA.set("forwardable", "true");
        sectionA.set("dns_lookup_realm", "false");

        ConfigImpl sectionB = new ConfigImpl("logging");
        rootConfig.set("logging", sectionB);
        sectionB.set("kdc", "FILE:/var/log/krb5kdc.log");

        Assert.assertEquals(rootConfig.getString("globalConfig"), "true");
        Assert.assertEquals(rootConfig.getString("default_realm"), null);

        Config subA = rootConfig.getConfig("libdefaults");
        Assert.assertEquals(subA.getString("default_realm"), "EXAMPLE.COM");
        Assert.assertEquals(subA.getString("globalConfig"), null);
        Assert.assertEquals(subA.getString("kdc"), null);

        Config subB = rootConfig.getConfig("logging");
        Assert.assertEquals(subB.getString("kdc"), "FILE:/var/log/krb5kdc.log");
        Assert.assertEquals(subB.getString("globalConfig"), null);
        Assert.assertEquals(subB.getBoolean("forwardable"), null);
    }
}
