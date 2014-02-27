package org.haox.kerb.codec.pac;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.haox.kerb.codec.DecodingException;

public class Pac {

    private PacLogonInfo logonInfo;
    private PacCredentialType credentialType;
    private PacSignature serverSignature;
    private PacSignature kdcSignature;

    public Pac(byte[] data, Key key) throws DecodingException {
        byte[] checksumData = data.clone();
        try {
            PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(
                    new ByteArrayInputStream(data)));

            if(data.length <= 8)
                throw new DecodingException("pac.token.empty", null, null);

            int bufferCount = pacStream.readInt();
            int version = pacStream.readInt();

            if(version != PacConstants.PAC_VERSION) {
                Object[] args = new Object[]{version};
                throw new DecodingException("pac.version.invalid", args, null);
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
            throw new DecodingException("pac.token.malformed", null, e);
        }

        PacMac mac = new PacMac();
        try {
            mac.init(key);
            mac.update(checksumData);
        } catch(NoSuchAlgorithmException e) {
            throw new DecodingException("pac.check.fail", null, e);
        }

        byte checksum[] = mac.doFinal();
        if(!Arrays.equals(serverSignature.getChecksum(), checksum))
            throw new DecodingException("pac.signature.invalid", null, null);
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
