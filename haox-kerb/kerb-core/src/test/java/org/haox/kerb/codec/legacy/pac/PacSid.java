package org.haox.kerb.codec.legacy.pac;

import org.haox.kerb.codec.legacy.DecodingException;

public class PacSid {

    private static final String FORMAT = "%1$02x";

    private byte revision;
    private byte subCount;
    private byte[] authority;
    private byte[] subs;

    public PacSid(byte[] bytes) throws DecodingException {
        if(bytes.length < 8 || ((bytes.length - 8) % 4) != 0
                || ((bytes.length - 8) / 4) != bytes[1])
            throw new DecodingException("pac.sid.malformed.size", null, null);

        this.revision = bytes[0];
        this.subCount = bytes[1];
        this.authority = new byte[6];
        System.arraycopy(bytes, 2, this.authority, 0, 6);
        this.subs = new byte[bytes.length - 8];
        System.arraycopy(bytes, 8, this.subs, 0, bytes.length - 8);
    }

    public PacSid(PacSid sid) {
        this.revision = sid.revision;
        this.subCount = sid.subCount;
        this.authority = new byte[6];
        System.arraycopy(sid.authority, 0, this.authority, 0, 6);
        this.subs = new byte[sid.subs.length];
        System.arraycopy(sid.subs, 0, this.subs, 0, sid.subs.length);
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();

        builder.append("\\").append(String.format(FORMAT, ((int)revision) & 0xff));
        builder.append("\\").append(String.format(FORMAT, ((int)subCount) & 0xff));
        for(int i = 0; i < authority.length; i++) {
            int unsignedByte = ((int)authority[i]) & 0xff;
            builder.append("\\").append(String.format(FORMAT, unsignedByte));
        }
        for(int i = 0; i < subs.length; i++) {
            int unsignedByte = ((int)subs[i]) & 0xff;
            builder.append("\\").append(String.format(FORMAT, unsignedByte));
        }

        return builder.toString();
    }

    public boolean isEmpty() {
        return subCount == 0;
    }

    public boolean isBlank() {
        boolean blank = true;
        for(byte sub : subs)
            blank = blank && (sub == 0);
        return blank;
    }

    public byte[] getBytes() {
        byte[] bytes = new byte[8 + subCount * 4];
        bytes[0] = revision;
        bytes[1] = subCount;
        System.arraycopy(authority, 0, bytes, 2, 6);
        System.arraycopy(subs, 0, bytes, 8, subs.length);

        return bytes;
    }

    public static String toString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();

        for(int i = 0; i < bytes.length; i++) {
            int unsignedByte = ((int)bytes[i]) & 0xff;
            builder.append("\\").append(String.format(FORMAT, unsignedByte));
        }

        return builder.toString();
    }

    public static PacSid createFromSubs(byte[] bytes) throws DecodingException {
        if((bytes.length % 4) != 0) {
            Object[] args = new Object[]{bytes.length};
            throw new DecodingException("pac.subauthority.malformed.size", args, null);
        }

        byte[] sidBytes = new byte[8 + bytes.length];
        sidBytes[0] = 1;
        sidBytes[1] = (byte)(bytes.length / 4);
        System.arraycopy(new byte[]{0, 0, 0, 0, 0, 5}, 0, sidBytes, 2, 6);
        System.arraycopy(bytes, 0, sidBytes, 8, bytes.length);

        return new PacSid(sidBytes);
    }

    public static PacSid append(PacSid sid1, PacSid sid2) {
        PacSid sid = new PacSid(sid1);

        sid.subCount += sid2.subCount;
        sid.subs = new byte[sid.subCount * 4];
        System.arraycopy(sid1.subs, 0, sid.subs, 0, sid1.subs.length);
        System.arraycopy(sid2.subs, 0, sid.subs, sid1.subs.length, sid2.subs.length);

        return sid;
    }

}
