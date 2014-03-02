package org.haox.kerb.spec.type.ap;

/**
 APOptions       ::= KrbFlags
 -- reserved(0),
 -- use-session-key(1),
 -- mutual-required(2)
 */
public enum ApOption {
    RESERVED(0x80000000),
    USE_SESSION_KEY(0x40000000),
    MUTUAL_REQUIRED(0x20000000),
    ETYPE_NEGOTIATION(0x00000002),
    USE_SUBKEY(0x00000001);

    private final int value;

    private ApOption(int value) {
        this.value = value;
    }
}