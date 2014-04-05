package org.haox.config;

import org.slf4j.LoggerFactory;

import java.util.*;

public class ConfigImpl implements Config {
	private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(Config.class);

    private String resource;
	private Map<String, ConfigObject> properties;
    private List<Config> subConfigs;

    private Set<String> propNames;

    protected ConfigImpl(String resource) {
        this.resource = resource;
        this.properties = new HashMap<String, ConfigObject>();
        this.subConfigs = new ArrayList<Config>(0);
    }

    @Override
    public String getResource() {
        return resource;
    }

    @Override
    public Set<String> getNames() {
        reloadNames();
        return propNames;
    }

    @Override
	public String getString(String name) {
		String result = null;

        ConfigObject co = properties.get(name);
		if (co != null) {
            result = co.getPropertyValue();
		}

        if (result == null) {
            for (Config sub : subConfigs) {
                result = sub.getString(name);
                if (result != null) break;
            }
        }

		return result;
	}

    @Override
    public String getString(String name, String defaultValue) {
        String result = getString(name);
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    @Override
    public String getTrimmed(String name) {
        String result = getString(name);
        if (null != result) {
            result = result.trim();
        }
        return result;
    }

    @Override
    public Integer getInt(String name) {
        Integer result = null;
        String value = getTrimmed(name);
        if (value != null) {
            result = Integer.valueOf(value);
        }
        return result;
    }

    @Override
    public Integer getInt(String name, int defaultValue) {
        Integer result = getInt(name);
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    @Override
    public Long getLong(String name) {
        Long result = null;
        String value = getTrimmed(name);
        if (value != null) {
            result = Long.valueOf(value);
        }
        return result;
    }

    @Override
    public Long getLong(String name, long defaultValue) {
        Long result = getLong(name);
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    @Override
    public Float getFloat(String name) {
        Float result = null;
        String value = getTrimmed(name);
        if (value != null) {
            result = Float.valueOf(value);
        }
        return result;
    }

    @Override
    public Float getFloat(String name, float defaultValue) {
        Float result = getFloat(name);
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    @Override
    public Boolean getBoolean(String name) {
        Boolean result = null;
        String value = getTrimmed(name);
        if (value != null) {
            result = Boolean.valueOf(value);
        }
        return result;
    }

    @Override
    public Boolean getBoolean(String name, boolean defaultValue) {
        Boolean result = getBoolean(name);
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    @Override
	public List<String> getList(String name) {
        List<String> results = null;
		ConfigObject co = properties.get(name);
		if (co != null) {
			results = co.getListValues();
		}
		return results;
	}

    @Override
    public Config getConfig(String name) {
        return null;
    }

    @Override
    public Class<?> getClass(String name, Class<?> defaultValue) throws ClassNotFoundException {
        Class<?> result = null;

        String valueString = getString(name);
        if (valueString == null) {
            result = defaultValue;
        } else {
            Class<?> cls = Class.forName(name);
            result = cls;
        }

        return result;
    }

    @Override
    public <T> T getInstance(String name) throws ClassNotFoundException {
        return getInstance(name, null);
    }

    @Override
    public <T> T getInstance(String name, Class<T> xface) throws ClassNotFoundException {
        T result = null;

        Class<?> cls = getClass(name, null);
        if (xface != null && !xface.isAssignableFrom(cls)) {
            throw new RuntimeException(cls + " does not implement " + xface);
        }
        try {
            result = (T) cls.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create instance with class " + cls.getName());
        }

        return result;
    }

    protected void set(String name, String value) {
		ConfigObject co = new ConfigObject(value);
		set(name, co);
	}

    protected void set(String name, Config value) {
        ConfigObject co = new ConfigObject(value);
        set(name, co);

        addSubConfig(value);
    }

    protected void set(String name, ConfigObject value) {
        this.properties.put(name, value);
    }

    private void addSubConfig(Config config) {
        this.subConfigs.add(config);
    }

    private void reloadNames() {
        if (propNames != null) {
            propNames.clear();
        }
        propNames = new HashSet<String>(properties.keySet());
        for (Config sub : subConfigs) {
            propNames.addAll(sub.getNames());
        }
    }
}
