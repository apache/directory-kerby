package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbEnum;

public enum SamType implements KrbEnum
{
    SAM_NONE(0),
    /** safe SAM type enum for Enigma Logic */
    SAM_TYPE_ENIGMA(1), // Enigma Logic"

    /** safe SAM type enum for Digital Pathways */
    SAM_TYPE_DIGI_PATH(2), // Digital Pathways

    /** safe SAM type enum for S/key where KDC has key 0 */
    SAM_TYPE_SKEY_K0(3), // S/key where KDC has key 0

    /** safe SAM type enum for Traditional S/Key */
    SAM_TYPE_SKEY(4), // Traditional S/Key

    /** safe SAM type enum for Security Dynamics */
    SAM_TYPE_SECURID(5), // Security Dynamics

    /** safe SAM type enum for CRYPTOCard */
    SAM_TYPE_CRYPTOCARD(6); // CRYPTOCard

    private int value;

    private SamType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static SamType fromValue(Integer value) {
        if (value != null) {
            for (SamType st : SamType.values() ) {
                if (value == st.getValue()) {
                    return st;
                }
            }
        }
        return SAM_NONE;
    }
}
