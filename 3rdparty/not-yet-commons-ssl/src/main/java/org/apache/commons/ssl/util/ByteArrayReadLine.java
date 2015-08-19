package org.apache.commons.ssl.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class ByteArrayReadLine extends ReadLine {

    public ByteArrayReadLine(ByteArrayInputStream in) { super(in); }

    public String next() { return next(1); }

    public String next(int lines) {
        try {
            return super.next(lines);
        } catch (IOException ioe) {
            // impossible since we're using ByteArrayInputStream
            throw new RuntimeException("impossible", ioe);
        }
    }

    public byte[] nextAsBytes() { return nextAsBytes(1); }

    public byte[] nextAsBytes(int lines) {
        try {
            return super.nextAsBytes(lines);
        } catch (IOException ioe) {
            // impossible since we're using ByteArrayInputStream
            throw new RuntimeException("impossible", ioe);
        }
    }

}
