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
package org.apache.kerby.config;

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

        Assert.assertEquals("true", rootConfig.getString("globalConfig"));
        Assert.assertNull(rootConfig.getString("default_realm"));//section config should not get the global value

        Config subA = rootConfig.getConfig("libdefaults");
        Assert.assertEquals("EXAMPLE.COM", subA.getString("default_realm"));
        Assert.assertNull(subA.getString("globalConfig"));
        Assert.assertNull(subA.getString("kdc"));

        Config subB = rootConfig.getConfig("logging");
        Assert.assertEquals("FILE:/var/log/krb5kdc.log", subB.getString("kdc"));
        Assert.assertNull(subB.getString("globalConfig"));
        Assert.assertNull(subB.getBoolean("forwardable"));
    }
}
