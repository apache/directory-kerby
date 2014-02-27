package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.KerberosTime;

/**
 EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
 ctime           [0] KerberosTime,
 cusec           [1] Microseconds,
 subkey          [2] EncryptionKey OPTIONAL,
 seq-number      [3] UInt32 OPTIONAL
 }
 */
public class EncAPRepPart {
    private KerberosTime ctime;
    private int cusec;
    private EncryptionKey subkey;
    private Integer seqNumber;

    public KerberosTime getCtime() {
        return ctime;
    }

    public void setCtime(KerberosTime ctime) {
        this.ctime = ctime;
    }

    public int getCusec() {
        return cusec;
    }

    public void setCusec(int cusec) {
        this.cusec = cusec;
    }

    public EncryptionKey getSubkey() {
        return subkey;
    }

    public void setSubkey(EncryptionKey subkey) {
        this.subkey = subkey;
    }

    public Integer getSeqNumber() {
        return seqNumber;
    }

    public void setSeqNumber(Integer seqNumber) {
        this.seqNumber = seqNumber;
    }
}
