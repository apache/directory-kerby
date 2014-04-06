package org.haox.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Conf {
    private static final Logger logger = LoggerFactory.getLogger(Conf.class);

	private List<ConfigLoader> resourceConfigs;
    private final ConfigImpl config;
    private boolean needReload;

	public Conf() {
        this.resourceConfigs = new ArrayList<ConfigLoader>(1);
        this.config = new ConfigImpl("Conf");
        this.needReload = true;
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
        needReload = true;
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
        if (needReload) {
            reload();
            needReload = false;
        }
        return config;
    }

    public void reload() {
        this.config.reset();
        if (resourceConfigs.size() == 1) {
            ConfigLoader loader = resourceConfigs.get(0);
            loader.setConfig(this.config);
            loader.load();
        } else {
            for (ConfigLoader loader : resourceConfigs) {
                Config loaded = loader.load();
                this.config.set(loaded.getResource(), loaded);
            }
        }
    }
}