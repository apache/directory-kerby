package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbEnum;
import org.haox.kerb.spec.type.KrbInteger;

public enum AuthorizationType implements KrbEnum {
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

    private final int value;

    private AuthorizationType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static AuthorizationType fromValue(KrbInteger value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.getValue().intValue()) {
                    return (AuthorizationType) e;
                }
            }
        }

        return NULL;
    }
}
