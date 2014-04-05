package org.haox.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Conf {
    private static final Logger LOG = LoggerFactory.getLogger(Conf.class);

	private List<ConfigLoader> resourceConfigs;
    private Config config;

	public Conf() {
        resourceConfigs = new ArrayList<ConfigLoader>(1);
	}

	public void addXmlConfig(File xmlFile) throws IOException {
        addResource(Resource.createXmlResource(xmlFile));
	}

    public void addIniConfig(File iniFile) throws IOException {
        addResource(Resource.createIniResource(iniFile));
    }

    public void addJsonConfig(File jsonFile) throws IOException {
        addResource(Resource.createJsonResource(jsonFile));
    }

    public void addResource(Resource resource) {
        ConfigLoader loader = getLoader(resource);
        resourceConfigs.add(loader);
    }

    private static ConfigLoader getLoader(Resource resource) {
        ConfigLoader loader = null;

        Class<? extends ConfigLoader> loaderClass = resource.getFormat().getLoaderClass();
        try {
            loader = loaderClass.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create org.haox.config loader for " + loaderClass.getName(), e);
        }
        loader.setResource(resource);
        return loader;
    }

    public Config getConfig() {
        if (config == null) {
            reload();
        }
        return config;
    }

    public void reload() {
        this.config = null;
        if (resourceConfigs.size() == 1) {
            ConfigLoader loader = resourceConfigs.get(0);
            this.config = loader.getConfig();
        } else {
            ConfigImpl configImpl = new ConfigImpl("Conf");
            for (ConfigLoader loader : resourceConfigs) {
                Config loaded = loader.getConfig();
                configImpl.set(loaded.getResource(), loaded);
            }
            this.config = configImpl;
        }
    }
}