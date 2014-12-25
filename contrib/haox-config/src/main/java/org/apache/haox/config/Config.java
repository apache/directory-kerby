package org.apache.haox.config;

import java.util.List;
import java.util.Set;

public interface Config {
    public String getResource();
    public Set<String> getNames();

    public String getString(String name);
    public String getString(ConfigKey name);
    public String getString(String name, String defaultValue);
    public String getTrimmed(String name);
    public String getTrimmed(ConfigKey name);
    public Boolean getBoolean(String name);
    public Boolean getBoolean(ConfigKey name);
    public Boolean getBoolean(String name, boolean defaultValue);
    public Integer getInt(String name);
    public Integer getInt(ConfigKey name);
    public Integer getInt(String name, int defaultValue);
    public Long getLong(String name);
    public Long getLong(ConfigKey name);
    public Long getLong(String name, long defaultValue);
    public Float getFloat(String name);
    public Float getFloat(ConfigKey name);
    public Float getFloat(String name, float defaultValue);
    public List<String> getList(String name);
    public List<String> getList(String name, String[] defaultValue);
    public List<String> getList(ConfigKey name);
    public Config getConfig(String name);
    public Config getConfig(ConfigKey name);

    public Class<?> getClass(String name) throws ClassNotFoundException;
    public Class<?> getClass(String name, Class<?> defaultValue) throws ClassNotFoundException;
    public Class<?> getClass(ConfigKey name) throws ClassNotFoundException;
    public <T> T getInstance(String name) throws ClassNotFoundException;
    public <T> T getInstance(ConfigKey name) throws ClassNotFoundException;
    public <T> T getInstance(String name, Class<T> xface) throws ClassNotFoundException;
}
