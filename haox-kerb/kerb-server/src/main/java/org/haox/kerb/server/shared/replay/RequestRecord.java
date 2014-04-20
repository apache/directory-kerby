package org.haox.kerb.server.shared.replay;

public class RequestRecord {
    private String clientPrincipal;
    private String serverPrincipal;
    private long requestTime;
    private int microseconds;

    public RequestRecord(String clientPrincipal, String serverPrincipal, long requestTime, int microseconds) {
        this.clientPrincipal = clientPrincipal;
        this.serverPrincipal = serverPrincipal;
        this.requestTime = requestTime;
        this.microseconds = microseconds;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RequestRecord that = (RequestRecord) o;

        if (microseconds != that.microseconds) return false;
        if (requestTime != that.requestTime) return false;
        if (!clientPrincipal.equals(that.clientPrincipal)) return false;
        if (!serverPrincipal.equals(that.serverPrincipal)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = clientPrincipal.hashCode();
        result = 31 * result + serverPrincipal.hashCode();
        result = 31 * result + (int) (requestTime ^ (requestTime >>> 32));
        result = 31 * result + microseconds;
        return result;
    }
}
