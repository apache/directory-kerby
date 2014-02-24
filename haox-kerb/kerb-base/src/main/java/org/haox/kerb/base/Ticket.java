package org.haox.kerb.base;

public class Ticket {
    public static final int TKT_KVNO = KrbConstant.KERBEROS_V5;

    private final int kvno = TKT_KVNO;
    private String sname;
    private String realm;
    private EncTicketPart encTicketPart;

    public int getKvno() {
        return kvno;
    }

    public String getSname() {
        return sname;
    }

    public void setSname(String sname) {
        this.sname = sname;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public EncTicketPart getEncTicketPart() {
        return encTicketPart;
    }

    public void setEncTicketPart(EncTicketPart encTicketPart) {
        this.encTicketPart = encTicketPart;
    }
}
