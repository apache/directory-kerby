package org.haox.kerb.spec;

public enum KrbCodecMessageCode implements KrbMessageCode {
    NOT_ENCODABLE;

    @Override
    public String getCodeName() {
        return name();
    }

}
