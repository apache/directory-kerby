package org.apache.kerberos.kerb.server.replay;

public interface CacheService
{
    boolean checkAndCache(RequestRecord request);
    void clear();
}
