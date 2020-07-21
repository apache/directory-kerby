package org.apache.kerby.kerberos.kerb.admin.message;

public class ChangePasswordReq extends AdminReq {
    public ChangePasswordReq() {
        super(AdminMessageType.CHANGE_PWD_REQ);
    }
}
