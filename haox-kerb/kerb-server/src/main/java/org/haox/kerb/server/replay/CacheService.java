package org.haox.kerb.server.replay;

public interface CacheService
{
    boolean checkAndCache(RequestRecord request);
    void clear();
}
