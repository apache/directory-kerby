package org.haox.kerb.server.shared.replay;

import org.haox.kerb.spec.type.common.KrbTime;

import javax.security.auth.kerberos.KerberosPrincipal;

/**
 * "The replay cache will identity at least the server name, along with the client name,
 * time, and microsecond fields from the recently-seen authenticators, and if a
 * matching tuple is found, the KRB_AP_ERR_REPEAT error is returned."
 */
public interface ReplayCache
{
    /**
     * Returns whether a request is a replay, based on the server principal, client
     * principal, time, and microseconds.
     * 
     * @param serverPrincipal The server principal 
     * @param clientPrincipal The client principal
     * @param clientTime The client time
     * @param clientMicroSeconds The client microsecond
     * @return true if the request is a replay.
     */
    boolean isReplay(KerberosPrincipal serverPrincipal, KerberosPrincipal clientPrincipal, KrbTime clientTime,
                     int clientMicroSeconds);


    /**
     * Saves the server principal, client principal, time, and microseconds to
     * the replay cache.
     *
     * @param serverPrincipal The server principal 
     * @param clientPrincipal The client principal
     * @param clientTime The client time
     * @param clientMicroSeconds The client microsecond
     */
    void save(KerberosPrincipal serverPrincipal, KerberosPrincipal clientPrincipal, KrbTime clientTime,
              int clientMicroSeconds);
    
    /**
     * removes all the elements present in the cache
     */
    void clear();
}
