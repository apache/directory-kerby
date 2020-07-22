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
package org.apache.kerby.kerberos.kerb.admin.message;

import org.apache.kerby.xdr.EnumType;

/**
 * Type of Admin Message:
 * NONE(-1)
 * ADD_PRINCIPAL_REQ(0) add principal request
 * ADD_PRINCIPAL_REP(1) add principal reply
 * DELETE_PRINCIPAL_REQ(2),
 * DELETE_PRINCIPAL_REP(3);
 * RENAME_PRINCIPAL_REQ(4),
 * RENAME_PRINCIPAL_REP(5);
 *
 */

public enum AdminMessageType implements EnumType {
    NONE(-1),
    ADD_PRINCIPAL_REQ(0),
    ADD_PRINCIPAL_REP(1),
    DELETE_PRINCIPAL_REQ(2),
    DELETE_PRINCIPAL_REP(3),
    RENAME_PRINCIPAL_REQ(4),
    RENAME_PRINCIPAL_REP(5),
    GET_PRINCS_REQ(6),
    GET_PRINCS_REP(7),
    EXPORT_KEYTAB_REQ(8),
    EXPORT_KEYTAB_REP(9),
    CHANGE_PWD_REQ(10),
    CHANGE_PWD_REP(11);

    private int value;

    AdminMessageType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    @Override
    public String getName() {
        return name();
    }

    public static AdminMessageType findType(int value) {
        if (value >= 0) {
            for (EnumType e : values()) {
                if (e.getValue() == value) {
                    return (AdminMessageType) e;
                }
            }
        }
        return NONE;
    }
}
