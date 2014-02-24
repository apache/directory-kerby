package org.haox.kerb.base;

public enum HostAddrType {
    /**
     * Constant for the "null" host address type.
     */
    NULL(0),

    /**
     * Constant for the "Internet" host address type.
     */
    ADDRTYPE_INET(2),

    /**
     * Constant for the "Arpanet" host address type.
     */
    ADDRTYPE_IMPLINK(3),

    /**
     * Constant for the "CHAOS" host address type.
     */
    ADDRTYPE_CHAOS(5),

    /**
     * Constant for the "XEROX Network Services" host address type.
     */
    ADDRTYPE_XNS(6),

    /**
     * Constant for the "OSI" host address type.
     */
    ADDRTYPE_OSI(7),

    /**
     * Constant for the "DECnet" host address type.
     */
    ADDRTYPE_DECNET(12),

    /**
     * Constant for the "AppleTalk" host address type.
     */
    ADDRTYPE_APPLETALK(16),

    /**
     * Constant for the "NetBios" host address type.
     *
     * Not in RFC
     */
    ADDRTYPE_NETBIOS(20),

    /**
     * Constant for the "Internet Protocol V6" host address type.
     */
    ADDRTYPE_INET6(24);


    private final int value;

    private HostAddrType(int value) {
        this.value = value;
    }
}
