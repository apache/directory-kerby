package org.haox.kerb.spec;

public enum KrbCodecMessageCode implements KrbMessageCode {
    NOT_ENCODABLE,
    DECODING_FAILED,
    NOT_IMPLEMENTED;

    @Override
    public String getCodeName() {
        return name();
    }

}
