package org.haox.kerb.server.shared.replay;

public interface CacheService
{
    boolean checkAndCache(RequestRecord request);
    void clear();
}
