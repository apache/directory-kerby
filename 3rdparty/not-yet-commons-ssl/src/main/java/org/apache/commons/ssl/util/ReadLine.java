package org.apache.commons.ssl.util;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Julius Davies
 * @author 23-Dec-2007
 */
public class ReadLine {

    final InputStream in;
    final byte[] bytes = new byte[8192];
    int pos = 0;
    int avail = 0;

    public ReadLine(InputStream in) { this.in = in; }

    public String next() throws IOException { return next(1); }

    public String next(int lines) throws IOException {
        if (lines < 1) {
            lines = 1;
        }
        StringBuffer buf = new StringBuffer(128 * lines);
        if (avail <= 0 || pos >= avail) {
            pos = 0;
            avail = in.read(bytes);
        }
        while (avail >= 0) {
            while (pos < avail) {
                char c = (char) bytes[pos++];
                switch (c) {
                    case '\n':
                    case '\r':
                        lines--;
                        if (lines < 1 && buf.length() > 0) {
                            return buf.toString();
                        }
                        break;
                    default:
                        buf.append(c);
                        break;
                }
            }
            pos = 0;
            avail = in.read(bytes);
        }
        return buf.length() > 0 ? buf.toString() : null;
    }

    public byte[] nextAsBytes() throws IOException { return nextAsBytes(1); }

    public byte[] nextAsBytes(int lines) throws IOException {
        if (lines < 1) {
            lines = 1;
        }
        byte[] buf = new byte[8192];
        int bufPos = 0;
        if (avail <= 0 || pos >= avail) {
            pos = 0;
            avail = in.read(bytes);
        }
        while (avail >= 0) {
            while (pos < avail) {
                byte b = bytes[pos++];
                switch (b) {
                    case '\n':
                    case '\r':
                        lines--;
                        if (lines == 0 && bufPos > 0) {
                            return buf;
                        }
                        break;
                    default:
                        if (bufPos >= buf.length) {
                            byte[] moreBuff = new byte[buf.length * 2];
                            System.arraycopy(buf, 0, moreBuff, 0, buf.length);
                            buf = moreBuff;
                        }
                        buf[bufPos++] = b;
                        break;
                }
            }
            pos = 0;
            avail = in.read(bytes);
        }
        return bufPos > 0 ? buf : null;
    }

}
