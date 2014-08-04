package org.haox.kerb.crypto2.enc;

import org.haox.kerb.crypto2.Crc32;
import org.haox.kerb.crypto2.cksum.provider.Crc32Provider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class DesCbcCrcEnc extends DesCbcEnc {

    public DesCbcCrcEnc() {
        super(new Crc32Provider());
    }

    public EncryptionType eType() {
        return EncryptionType.DES_CBC_CRC;
    }

    public int minimumPadSize() {
        return 4;
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType checksumType() {
        return CheckSumType.CRC32;
    }

    public int checksumSize() {
        return 4;
    }
}
