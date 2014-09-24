package org.haox.kerb.server.replay;

public class ReplayCheckServiceImpl implements ReplayCheckService
{
    private CacheService cacheService;

    public ReplayCheckServiceImpl(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    public ReplayCheckServiceImpl() {
        this(new SimpleCacheService());
    }

    @Override
    public boolean checkReplay(String clientPrincipal, String serverPrincipal,
                               long requestTime, int microseconds) {
        RequestRecord record = new RequestRecord(clientPrincipal, serverPrincipal, requestTime, microseconds);
        return cacheService.checkAndCache(record);
    }
}
