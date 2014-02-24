package org.haox.kerb.base;

public enum KrbNameType {
    KRB_NT_UNKNOWN(0),
    KRB_NT_PRINCIPAL(1),
    KRB_NT_SRV_INST(2),
    KRB_NT_SRV_HST(3),
    KRB_NT_SRV_XHST(4),
    KRB_NT_UID(5);
    
    private int value;

    private KrbNameType(int value) {
        this.value = value;
    }
}
