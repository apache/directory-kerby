// automatically generated, do not modify

package org.apache.kerby.kerberos.kdc.identitybackend;

import java.nio.*;
import java.lang.*;
import java.util.*;
import com.google.flatbuffers.*;

@SuppressWarnings("unused")
public final class FbsEncryptionKey extends Table {
  public static FbsEncryptionKey getRootAsFbsEncryptionKey(ByteBuffer _bb) { return getRootAsFbsEncryptionKey(_bb, new FbsEncryptionKey()); }
  public static FbsEncryptionKey getRootAsFbsEncryptionKey(ByteBuffer _bb, FbsEncryptionKey obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__init(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public FbsEncryptionKey __init(int _i, ByteBuffer _bb) { bb_pos = _i; bb = _bb; return this; }

  public int keyType() { int o = __offset(4); return o != 0 ? bb.getInt(o + bb_pos) : 0; }
  public boolean mutateKeyType(int keyType) { int o = __offset(4); if (o != 0) { bb.putInt(o + bb_pos, keyType); return true; } else { return false; } }
  public byte keyValue(int j) { int o = __offset(6); return o != 0 ? bb.get(__vector(o) + j * 1) : 0; }
  public int keyValueLength() { int o = __offset(6); return o != 0 ? __vector_len(o) : 0; }
  public ByteBuffer keyValueAsByteBuffer() { return __vector_as_bytebuffer(6, 1); }
  public boolean mutateKeyValue(int j, byte keyValue) { int o = __offset(6); if (o != 0) { bb.put(__vector(o) + j * 1, keyValue); return true; } else { return false; } }

  public static int createFbsEncryptionKey(FlatBufferBuilder builder,
      int keyType,
      int keyValue) {
    builder.startObject(2);
    FbsEncryptionKey.addKeyValue(builder, keyValue);
    FbsEncryptionKey.addKeyType(builder, keyType);
    return FbsEncryptionKey.endFbsEncryptionKey(builder);
  }

  public static void startFbsEncryptionKey(FlatBufferBuilder builder) { builder.startObject(2); }
  public static void addKeyType(FlatBufferBuilder builder, int keyType) { builder.addInt(0, keyType, 0); }
  public static void addKeyValue(FlatBufferBuilder builder, int keyValueOffset) { builder.addOffset(1, keyValueOffset, 0); }
  public static int createKeyValueVector(FlatBufferBuilder builder, byte[] data) { builder.startVector(1, data.length, 1); for (int i = data.length - 1; i >= 0; i--) builder.addByte(data[i]); return builder.endVector(); }
  public static void startKeyValueVector(FlatBufferBuilder builder, int numElems) { builder.startVector(1, numElems, 1); }
  public static int endFbsEncryptionKey(FlatBufferBuilder builder) {
    int o = builder.endObject();
    return o;
  }
};

