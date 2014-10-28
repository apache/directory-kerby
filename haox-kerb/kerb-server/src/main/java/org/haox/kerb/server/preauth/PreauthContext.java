package org.haox.kerb.server.preauth;

import org.haox.kerb.identity.KrbIdentity;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.nio.ByteBuffer;
import java.util.List;

public interface PreauthContext {

    /**
     * Get the client keys matching request enctypes.
     */
    public List<EncryptionKey> getClientKeys() throws KrbException;

    public KrbIdentity getClientEntry() throws KrbException;

    /**
     * Get the encoded request body, which is sometimes needed for checksums.
     * For a FAST request this is the encoded inner request body.
     */
    public abstract ByteBuffer getRequestBody() throws KrbException;

    /**
     * Get the FAST armor key, or NULL if the client is not using FAST.
     */
    public EncryptionKey getArmorKey() throws KrbException;
}
