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

import org.apache.haox.config.Conf;
import org.apache.haox.config.ConfigKey;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * The test is base on the Conf level.
 * We hope users use the Conf object only, and don't need to care about its internal implementation.
 */
public class ConfTest {

    @Test
    public void testMapConfig() {
        String strProp = "hello";
        Integer intProp = 123456;
        Boolean boolProp = true;
        Map<String, String> mapConfig = new HashMap<String, String>();
        mapConfig.put("strProp", strProp);
        mapConfig.put("intProp", String.valueOf(intProp));
        mapConfig.put("boolProp", String.valueOf(boolProp));

        Conf conf = new Conf();
        conf.addMapConfig(mapConfig);
        Assert.assertEquals(conf.getString("strProp"), strProp);
        Assert.assertEquals(conf.getInt("intProp"), intProp);
        Assert.assertEquals(conf.getBoolean("boolProp"), boolProp);
    }

    @Test
    public void testPropertiesConfig() {
        String strProp = "hello";
        Integer intProp = 123456;
        Boolean boolProp = true;
        Properties properties = new Properties();
        properties.setProperty("strProp", strProp);
        properties.setProperty("intProp", String.valueOf(intProp));
        properties.setProperty("boolProp", String.valueOf(boolProp));

        Conf conf = new Conf();
        conf.addPropertiesConfig(properties);
        Assert.assertEquals(conf.getString("strProp"), strProp);
        Assert.assertEquals(conf.getInt("intProp"), intProp);
        Assert.assertEquals(conf.getBoolean("boolProp"), boolProp);
    }

    /**
     * Test for whether can get right value form the conf which contains many config resources.
     */
    @Test
    public void testMixedConfig() {
        String mapStrProp = "hello map";
        Integer intProp = 123456;
        Map<String, String> mapConfig = new HashMap<String, String>();
        mapConfig.put("mapStrProp", mapStrProp);
        mapConfig.put("intProp", String.valueOf(intProp));

        String propertiesStrProp = "hello properties";
        Boolean boolProp = true;
        Properties properties = new Properties();
        properties.setProperty("propertiesStrProp", propertiesStrProp);
        properties.setProperty("boolProp", String.valueOf(boolProp));

        Conf conf = new Conf();
        conf.addMapConfig(mapConfig);
        conf.addPropertiesConfig(properties);
        Assert.assertEquals(conf.getConfig("mapConfig"), null);
        Assert.assertEquals(conf.getString("mapStrProp"), mapStrProp);
        Assert.assertEquals(conf.getString("propertiesStrProp"), propertiesStrProp);
        Assert.assertEquals(conf.getInt("intProp"), intProp);
        Assert.assertEquals(conf.getBoolean("boolProp"), boolProp);
    }

    static enum TestConfKey implements ConfigKey {
        ADDRESS("127.0.0.1"),
        PORT(8015),
        ENABLE(false);

        private Object defaultValue;

        private TestConfKey(Object defaultValue) {
            this.defaultValue = defaultValue;
        }

        @Override
        public String getPropertyKey() {
            return name().toLowerCase();
        }

        @Override
        public Object getDefaultValue() {
            return this.defaultValue;
        }
    }

    @Test
    public void testConfKey() {
        Conf conf = new Conf();
        Assert.assertEquals(conf.getString(TestConfKey.ADDRESS),
                TestConfKey.ADDRESS.getDefaultValue());
        Map<String, String> mapConfig = new HashMap<String, String>();
        String myAddress = "www.google.com";
        mapConfig.put(TestConfKey.ADDRESS.getPropertyKey(), myAddress);
        conf.addMapConfig(mapConfig);
        Assert.assertEquals(conf.getString(TestConfKey.ADDRESS), myAddress);
        Assert.assertEquals(conf.getInt(TestConfKey.PORT),
                TestConfKey.PORT.getDefaultValue());
        Assert.assertEquals(conf.getBoolean(TestConfKey.ENABLE),
                TestConfKey.ENABLE.getDefaultValue());
    }
}
