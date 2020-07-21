package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageType;
import org.apache.kerby.kerberos.kerb.admin.message.ChangePasswordReq;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ChangePasswordRequest extends AdminRequest {
    
    private String newPassword = null;
    
    public ChangePasswordRequest(String principal, String newPassword) {
        super(principal);
        this.newPassword = newPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    @Override
    public void process() throws KrbException {
        super.process();

        ChangePasswordReq changePwdReq = new ChangePasswordReq();

        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[4];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.CHANGE_PWD_REQ);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 2);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, getPrincipal());
        xdrFieldInfos[3] = new XdrFieldInfo(3, XdrDataType.STRING, getNewPassword());

        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        byte[] encodeBytes;
        try {
            encodeBytes = value.encode();
        } catch (IOException e) {
            throw new KrbException("Xdr encode error when generate get principals request.", e);
        }
        ByteBuffer messageBuffer = ByteBuffer.wrap(encodeBytes);
        changePwdReq.setMessageBuffer(messageBuffer);

        setAdminReq(changePwdReq);
    }
}
