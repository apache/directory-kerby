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
package org.apache.kerby.kerberos.kerb.preauth.pkinit;

/*
 * Ref. cms_msg_types in MIT krb5 project.
 */
public enum CmsMessageType {
    UNKNOWN                  (-1),
    CMS_SIGN_CLIENT          (0x01),
    CMS_SIGN_SERVER          (0x03),
    CMS_ENVEL_SERVER         (0x04);


    /** The type value */
    private int value;

    /**
     * Create an instance of this class
     */
    CmsMessageType(int value) {
        this.value = value;
    }

    /**
     * @return The associated type value
     */
    public int getValue() {
        return value;
    }

    /**
     * Retrieve the UniversalTag associated with a given value
     * @param value The integer value
     * @return The associated UniversalTag
     */
    public static CmsMessageType fromValue(int value) {
        switch (value) {
            case 0x01 : return CMS_SIGN_CLIENT;
            case 0x03 : return CMS_SIGN_SERVER;
            case 0x04 : return CMS_ENVEL_SERVER;
            default : return UNKNOWN;
        }
    }
}
