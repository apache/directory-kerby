package org.haox.kerb.codec.pac;

import org.haox.kerb.crypto2.CheckSumHandler;
import org.haox.kerb.crypto2.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSum;
import org.haox.kerb.spec.type.common.EncryptionKey;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Pac {

    private PacLogonInfo logonInfo;
    private PacCredentialType credentialType;
    private PacSignature serverSignature;
    private PacSignature kdcSignature;

    public Pac(byte[] data, byte[] key) throws KrbException {
        byte[] checksumData = data.clone();
        try {
            PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(
                    new ByteArrayInputStream(data)));

            if(data.length <= 8)
                throw new IOException("pac.token.empty");

            int bufferCount = pacStream.readInt();
            int version = pacStream.readInt();

            if(version != PacConstants.PAC_VERSION) {
                Object[] args = new Object[]{version};
                throw new IOException("pac.version.invalid");
            }

            for(int bufferIndex = 0; bufferIndex < bufferCount; bufferIndex++) {
                int bufferType = pacStream.readInt();
                int bufferSize = pacStream.readInt();
                long bufferOffset = pacStream.readLong();
                byte[] bufferData = new byte[bufferSize];
                System.arraycopy(data, (int)bufferOffset, bufferData, 0, bufferSize);

                switch (bufferType) {
                case PacConstants.LOGON_INFO:
                    // PAC Credential Information
                    logonInfo = new PacLogonInfo(bufferData);
                    break;
                case PacConstants.CREDENTIAL_TYPE:
                    // PAC Credential Type
                    credentialType = new PacCredentialType(bufferData);
                    break;
                case PacConstants.SERVER_CHECKSUM:
                    // PAC Server Signature
                    serverSignature = new PacSignature(bufferData);
                    // Clear signature from checksum copy
                    for(int i = 0; i < bufferSize; i++)
                        checksumData[(int)bufferOffset + 4 + i] = 0;
                    break;
                case PacConstants.PRIVSVR_CHECKSUM:
                    // PAC KDC Signature
                    kdcSignature = new PacSignature(bufferData);
                    // Clear signature from checksum copy
                    for(int i = 0; i < bufferSize; i++)
                        checksumData[(int)bufferOffset + 4 + i] = 0;
                    break;
                default:
                }
            }
        } catch(IOException e) {
            throw new KrbException("pac.token.malformed", e);
        }

        CheckSum checksum = new CheckSum(serverSignature.getType(), serverSignature.getChecksum());
        CheckSumHandler.verifyChecksumWithKey(checksum, checksumData, key, KeyUsage.KERB_NON_KERB_CKSUM_SALT);
    }

    public PacLogonInfo getLogonInfo() {
        return logonInfo;
    }

    public PacCredentialType getCredentialType() {
        return credentialType;
    }

    public PacSignature getServerSignature() {
        return serverSignature;
    }

    public PacSignature getKdcSignature() {
        return kdcSignature;
    }
}
