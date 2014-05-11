package org.haox.kerb.spec;

public enum CodecMessageCode implements MessageCode {
    NOT_ENCODABLE,
    DECODING_FAILED,
    NOT_IMPLEMENTED;

    @Override
    public String getCodeName() {
        return name();
    }

}
