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
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.config.ConfigKey;

/**
 * Define all the MySQL backend related configuration items with default values.
 */
public enum MySQLConfKey implements ConfigKey {
    MYSQL_DRIVER("org.drizzle.jdbc.DrizzleDriver"),
    MYSQL_URL("jdbc:mysql:thin://127.0.0.1:3306/mysqlbackend"),
    MYSQL_USER("root"),
    MYSQL_PASSWORD("passwd");

    private Object defaultValue;

    MySQLConfKey() {
        this.defaultValue = null;
    }

    MySQLConfKey(Object defaultValue) {
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
