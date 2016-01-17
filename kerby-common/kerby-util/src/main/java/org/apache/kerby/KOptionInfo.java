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
package org.apache.kerby;

public class KOptionInfo {
    private String name;
    private KOptionGroup group;
    private KOptionType type;
    private String description;
    private Object value;

    public KOptionInfo(String name, String description) {
        this(name, description, KOptionType.NOV);
    }

    public KOptionInfo(String name, String description, KOptionType type) {
        this(name, description, null, type);
    }

    public KOptionInfo(String name, String description, KOptionGroup group) {
        this(name, description, group, KOptionType.NOV);
    }

    public KOptionInfo(String name, String description,
              KOptionGroup group, KOptionType type) {
        this.name = name;
        this.description = description;
        this.group = group;
        this.type = type;
    }

    /**
     * Set koption type.
     *
     * @param type The type
     */
    public void setType(KOptionType type) {
        this.type = type;
    }

    /**
     * Get koption type.
     *
     * @return The koption type
     */
    public KOptionType getType() {
        return type;
    }

    /**
     * Set name.
     *
     * @param name The name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get name.
     *
     * @return The name
     */
    public String getName() {
        return name;
    }


    /**
     * Set description.
     *
     * @param description The description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Get description.
     *
     * @return The description
     */
    public String getDescription() {
        return description;
    }


    /**
     * Set value.
     *
     * @param value The value
     */
    public void setValue(Object value) {
        this.value = value;
    }


    /**
     * Get value.
     *
     * @return The value
     */
    public Object getValue() {
        return value;
    }

    /**
     * Set group.
     *
     * @param group The group
     */
    public void setGroup(KOptionGroup group) {
        this.group = group;
    }

    /**
     * Get group.
     *
     * @return The group
     */
    public KOptionGroup getGroup() {
        return group;
    }
}

