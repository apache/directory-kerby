package org.haox.kerb.common.crypto.encryption;

import org.haox.kerb.spec.type.KrbEnum;

public enum  KeyUsage implements KrbEnum
{
    UNKNOWN(-1),

    // AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client key
    AS_REQ_PA_ENC_TIMESTAMP_WITH_CKEY(1),

    // AS-REP Ticket and TGS-REP Ticket (includes TGS session key or application session key), encrypted with the service key (Section 5.3)
    AS_OR_TGS_REP_TICKET_WITH_SRVKEY(2),

    // AS-REP encrypted part (includes TGS session key or application session key), encrypted with the client key (Section 5.4.2)
    AS_REP_ENC_PART_WITH_CKEY(3),

    // TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS session key (Section 5.4.1)
    TGS_REQ_KDC_REQ_BODY_AUTHZ_DATA_ENC_WITH_TGS_SESS_KEY(4),

    // TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS authenticator subkey (Section 5.4.1)
    TGS_REQ_KDC_REQ_BODY_AUTHZ_DATA_ENC_WITH_AUTHNT_SUB_KEY(5),

    // TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum, keyed with the TGS session key (Section 5.5.1)
    TGS_REQ_PA_TGS_REQ_PADATA_AP_REQ_AUTHNT_CKSUM_TGS_SESS_KEY(6),

    // TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes TGS authenticator subkey), encrypted with the TGS session key (Section 5.5.1)
    TGS_REQ_PA_TGS_REQ_PADATA_AP_REQ_TGS_SESS_KEY(7),

    // TGS-REP encrypted part (includes application session key), encrypted with the TGS session key (Section 5.4.2)
    TGS_REP_ENC_PART_TGS_SESS_KEY(8),

    // TGS-REP encrypted part (includes application session key), encrypted with the TGS authenticator subkey (Section 5.4.2)
    TGS_REP_ENC_PART_TGS_AUTHNT_SUB_KEY(9),

    // AP-REQ Authenticator cksum, keyed with the application session key (Section 5.5.1)
    AP_REQ_AUTHNT_CKSUM_SESS_KEY(10),

    // AP-REQ Authenticator (includes application authenticator subkey), encrypted with the application session key (Section 5.5.1)
    AP_REQ_AUTHNT_SESS_KEY(11),

    // AP-REP encrypted part (includes application session subkey), encrypted with the application session key (Section 5.5.2)
    AP_REP_ENC_PART_SESS_KEY(12),

    // KRB-PRIV encrypted part, encrypted with a key chosen by the application (Section 5.7.1)
    KRB_PRIV_ENC_PART_CHOSEN_KEY(13);

    private int value;

    private KeyUsage(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static KeyUsage fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value) {
                    return (KeyUsage) e;
                }
            }
        }
        return UNKNOWN;
    }
}
