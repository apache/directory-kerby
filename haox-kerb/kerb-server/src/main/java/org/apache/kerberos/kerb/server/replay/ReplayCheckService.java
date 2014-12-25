package org.apache.kerberos.kerb.server.replay;

public interface ReplayCheckService
{
    boolean checkReplay(String clientPrincipal, String serverPrincipal, long requestTime, int microseconds);
}
