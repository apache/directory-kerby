package org.haox.config;

import junit.framework.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

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
