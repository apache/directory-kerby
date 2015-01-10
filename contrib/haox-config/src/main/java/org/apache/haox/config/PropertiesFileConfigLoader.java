package org.apache.haox.config;

import java.io.InputStream;
import java.util.Properties;

public class PropertiesFileConfigLoader extends PropertiesConfigLoader {

    @Override
    protected void loadConfig(ConfigImpl config, Resource resource) throws Exception {
        Properties propConfig = new Properties();
        propConfig.load((InputStream) resource.getResource());
        loadConfig(config, propConfig);
    }
}
