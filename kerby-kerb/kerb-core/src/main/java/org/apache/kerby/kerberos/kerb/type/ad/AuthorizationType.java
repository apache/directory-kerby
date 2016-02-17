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
package org.apache.kerby.kerberos.kerb.type.ad;

import org.apache.kerby.asn1.EnumType;

/**
 * The various AuthorizationType values, as defined in RFC 4120 and RFC 1510.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum AuthorizationType implements EnumType {
    /**
     * Constant for the "null" authorization type.
     */
    NULL(0),

    /**
     * Constant for the "if relevant" authorization type.
     *
     * RFC 4120
     */
    AD_IF_RELEVANT(1),

    /**
     * Constant for the "intended for server" authorization type.
     *
     * RFC 4120
     */
    AD_INTENDED_FOR_SERVER(2),

    /**
     * Constant for the  "intended for application class" authorization type.
     *
     * RFC 4120
     */
    AD_INTENDED_FOR_APPLICATION_CLASS(3),

    /**
     * Constant for the "kdc issued" authorization type.
     *
     * RFC 4120
     */
    AD_KDC_ISSUED(4),

    /**
     * Constant for the "or" authorization type.
     *
     * RFC 4120
     */
    AD_OR(5),

    /**
     * Constant for the "mandatory ticket extensions" authorization type.
     *
     * RFC 4120
     */
    AD_MANDATORY_TICKET_EXTENSIONS(6),

    /**
     * Constant for the "in ticket extensions" authorization type.
     *
     * RFC 4120
     */
    AD_IN_TICKET_EXTENSIONS(7),

    /**
     * Constant for the "mandatory-for-kdc" authorization type.
     *
     * RFC 4120
     */
    AD_MANDATORY_FOR_KDC(8),

    /**
     * Constant for the "OSF DCE" authorization type.
     *
     * RFC 1510
     */
    OSF_DCE(64),

    /**
     * Constant for the "sesame" authorization type.
     *
     * RFC 1510
     */
    SESAME(65),

    /**
     * Constant for the "OSF-DCE pki certid" authorization type.
     *
     * RFC 1510
     */
    AD_OSF_DCE_PKI_CERTID(66),

    /**
     * Constant for the "sesame" authorization type.
     *
     * RFC 1510
     */
    AD_WIN2K_PAC(128),

    /**
     * Constant for the "sesame" authorization type.
     *
     * RFC 1510
     */
    AD_ETYPE_NEGOTIATION(129);

    /** The internal value */
    private final int value;

    /**
     * Create a new enum 
     */
    AuthorizationType(int value) {
        this.value = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return name();
    }

    /**
     * Get the AuthorizationType associated with a value.
     * 
     * @param value The integer value of the AuthorizationType we are looking for
     * @return The associated AuthorizationType, or NULL if not found or if value is null
     */
    public static AuthorizationType fromValue(Integer value) {
        if (value != null) {
            for (EnumType e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (AuthorizationType) e;
                }
            }
        }

        return NULL;
    }
}
