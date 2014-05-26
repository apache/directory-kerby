package org.haox.kerb.codec.pac;

import java.io.IOException;

/**
 * Structure representing the PAC_CREDENTIAL_TYPE record
 * 
 * @author jbbugeau
 */
public class PacCredentialType {

    private static final int MINIMAL_BUFFER_SIZE = 32;

    private byte[] credentialType;

    public PacCredentialType(byte[] data) throws IOException {
        credentialType = data;
        if(!isCredentialTypeCorrect()) {
            throw new IOException("pac.credentialtype.malformed");
        }
    }

    public boolean isCredentialTypeCorrect() {
        return credentialType != null && credentialType.length < MINIMAL_BUFFER_SIZE;
    }

}
