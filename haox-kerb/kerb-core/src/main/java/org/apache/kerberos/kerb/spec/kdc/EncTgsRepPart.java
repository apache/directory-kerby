package org.apache.kerberos.kerb.spec.kdc;

/**
 EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
 */
public class EncTgsRepPart extends EncKdcRepPart {
    public static final int TAG = 26;

    public EncTgsRepPart() {
        super(TAG);
    }
}
