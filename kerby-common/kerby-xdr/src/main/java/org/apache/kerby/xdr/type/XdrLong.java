package org.apache.kerby.xdr.type;

import org.apache.kerby.xdr.XdrDataType;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * From RFC 4506 :
 * 
 *         (MSB)                                                   (LSB)
 *       +-------+-------+-------+-------+-------+-------+-------+-------+
 *       |byte 0 |byte 1 |byte 2 |byte 3 |byte 4 |byte 5 |byte 6 |byte 7 |
 *       +-------+-------+-------+-------+-------+-------+-------+-------+
 *       <----------------------------64 bits---------------------------->
 *                                                  HYPER INTEGER
 *                                                  UNSIGNED HYPER INTEGER
 */
public class XdrLong extends XdrSimple<Long> {
    public XdrLong() {
        this((Long) null);
    }
    
    public XdrLong(Long value) {
        super(XdrDataType.LONG, value);
    }

    /**
     * The length of a signed long is 8.
     * @return Length of a signed long type.
     */
    @Override
    protected int encodingBodyLength() throws IOException {
        return 8;
    }

    /**
     * Encode Long type to bytes.
     * Cannot only use toByteArray() because of fixed 4 bytes length.
     */
    @Override
    protected void toBytes() throws IOException {
        long value = getValue().longValue();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(value);
        buffer.flip();
        setBytes(buffer.array());
    }

    /**
     * Decode bytes to Long value.
     */
    @Override
    protected void toValue() {
        if (getBytes().length != 8) {
            byte[] longBytes = ByteBuffer.allocate(8).put(getBytes(), 0, 8).array();
            /**reset bytes in case the enum type is in a struct or union*/
            setBytes(longBytes);
        }
        ByteBuffer buffer = ByteBuffer.wrap(getBytes());
        setValue(buffer.getLong());
    }
}
