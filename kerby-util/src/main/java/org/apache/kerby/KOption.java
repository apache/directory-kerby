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

public interface KOption {

    /**
     * Set koption type.
     *
     * @param type The type
     */
    void setType(KOptionType type);

    /**
     * Get koption type.
     *
     * @return The koption type
     */
    KOptionType getType();

    /**
     * Get option name.
     *
     * @return The koption name
     */
    String getOptionName();


    /**
     * Set name.
     *
     * @param name The name
     */
    void setName(String name);

    /**
     * Get name.
     *
     * @return The name
     */
    String getName();


    /**
     * Set description.
     *
     * @param description The description
     */
    void setDescription(String description);

    /**
     * Get description.
     *
     * @return The description
     */
    String getDescription();


    /**
     * Set value.
     *
     * @param value The value
     */
    void setValue(Object value);


    /**
     * Get value.
     *
     * @return The value
     */
    Object getValue();
}

