package org.haox.kerb.server.shared.replay;

public interface ReplayCheckService
{
    boolean checkReplay(String clientPrincipal, String serverPrincipal, long requestTime, int microseconds);
}
