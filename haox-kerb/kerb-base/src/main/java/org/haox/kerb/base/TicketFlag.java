package org.haox.kerb.base;

public enum TicketFlag {
    FORWARDABLE(0x40000000),
    FORWARDED(0x20000000),
    PROXIABLE(0x10000000),
    PROXY(0x08000000),
    MAY_POSTDATE(0x04000000),
    POSTDATED(0x02000000),
    INVALID(0x01000000),
    RENEWABLE(0x00800000),
    INITIAL(0x00400000),
    PRE_AUTH(0x00200000),
    HW_AUTH(0x00100000),
    TRANSIT_POLICY_CHECKED(  0x00080000),
    OK_AS_DELEGATE(0x00040000),
    ENC_PA_REP(0x00010000),
    ANONYMOUS(0x00008000);

    private final int value;

    private TicketFlag(int value) {
        this.value = value;
    }
}
