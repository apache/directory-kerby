package org.haox.kerb.spec.type.kdc;

/**
 EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
 */
public class EncTgsRepPart extends EncKdcRepPart {
    public static final int TAG = 26;

    public EncTgsRepPart() {
        super(TAG);
    }
}
