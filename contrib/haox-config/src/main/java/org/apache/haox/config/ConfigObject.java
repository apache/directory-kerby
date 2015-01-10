package org.apache.haox.config;

import java.util.ArrayList;
import java.util.List;

public class ConfigObject {
	protected static enum VALUE_TYPE { PROPERTY, LIST, CONFIG };
		
	private VALUE_TYPE valueType;
	private Object value;
	
	public ConfigObject(String value) {
		this.value = value;
		this.valueType = VALUE_TYPE.PROPERTY;
	}
	
	public ConfigObject(String[] values) {
		List<String> valuesList = new ArrayList<String>();
		for (String v : values) {
			valuesList.add(v);
		}

		this.value = valuesList;
		this.valueType = VALUE_TYPE.LIST;
	}

    public ConfigObject(List<String> values) {
        this.value = new ArrayList<String>(values);
        this.valueType = VALUE_TYPE.LIST;
    }

	public ConfigObject(Config value) {
		this.value = value;
		this.valueType = VALUE_TYPE.CONFIG;
	}

	public String getPropertyValue() {
		String result = null;
		if (valueType == VALUE_TYPE.PROPERTY) {
			result = (String) value;
		}
		return result;
	}
	
	public List<String> getListValues() {
		List<String> results = null;
		if (valueType == VALUE_TYPE.LIST) {
            results = (List<String>) value;
		}
		
		return results;
	}

	public Config getConfigValue() {
		Config result = null;
		if (valueType == VALUE_TYPE.CONFIG) {
			result = (Config) value;
		}
		return result;
	}
}
