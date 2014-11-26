package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

public class PreauthCallback {

    /**
     * Get the client-supplied reply key, possibly derived from password
     */
    public EncryptionKey getAsKey(KrbContext krbContext,
                                  KdcRequest kdcRequest) throws KrbException {
        return kdcRequest.getAsKey();
    }

    /**
     * Replace the reply key to be used to decrypt the AS response.
     */
    public void setAsKey(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         EncryptionKey asKey) {

        kdcRequest.setAsKey(asKey);
    }

    /**
     * Indicate interest in the AS key.
     */
    public void needAsKey(KrbContext krbContext,
                          KdcRequest kdcRequest) throws KrbException {

        EncryptionKey clientKey = kdcRequest.getClientKey();
        if (clientKey == null) {
            throw new RuntimeException("Client key should be prepared or prompted at this time!");
        }
        kdcRequest.setAsKey(clientKey);
    }

    /**
     * Get the enctype expected to be used to encrypt the encrypted portion of
     * the AS_REP packet.  When handling a PREAUTH_REQUIRED error, this
     * typically comes from etype-info2.  When handling an AS reply, it is
     * initialized from the AS reply itself.
     */
    public EncryptionType getEncType(KrbContext krbContext,
                                     KdcRequest kdcRequest) {

        return kdcRequest.getChosenEncryptionType();
    }

    public void askQuestion(KrbContext krbContext,
                              KdcRequest kdcRequest,
                              String question,
                              String challenge) {

        kdcRequest.getResponser().askQuestion(question, challenge);
    }

    /**
     * Get a pointer to the FAST armor key, or NULL if the client is not using FAST.
     */
    public EncryptionKey getArmorKey(KrbContext krbContext,
                                     KdcRequest kdcRequest) {

        return kdcRequest.getFastContext().armorKey;
    }

    /**
     * Get the current time for use in a preauth response.  If
     * allow_unauth_time is true and the library has been configured to allow
     * it, the current time will be offset using unauthenticated timestamp
     * information received from the KDC in the preauth-required error, if one
     * has been received.  Otherwise, the timestamp in a preauth-required error
     * will only be used if it is protected by a FAST channel.  Only set
     * allow_unauth_time if using an unauthenticated time offset would not
     * create a security issue.
     */
    public KerberosTime getPreauthTime(KrbContext krbContext,
                                       KdcRequest kdcRequest) {
        return KerberosTime.now();
    }

    /**
     * Get a state item from an input ccache, which may allow it
     * to retrace the steps it took last time.  The returned data string is an
     * alias and should not be freed.
     */
    public Object getCacheValue(KrbContext krbContext,
                                         KdcRequest kdcRequest,
                                         String key) {

        return kdcRequest.getCredCache().get(key);
    }

    /**
     * Set a state item which will be recorded to an output
     * ccache, if the calling application supplied one.  Both key and data
     * should be valid UTF-8 text.
     */
    public void cacheValue(KrbContext krbContext,
                                    KdcRequest kdcRequest,
                                    String key,
                                    Object value) {

        kdcRequest.getCredCache().put(key, value);
    }

}
