// automatically generated, do not modify

package org.apache.kerby.kerberos.kdc.identitybackend;

import java.nio.*;
import java.lang.*;
import java.util.*;
import com.google.flatbuffers.*;

@SuppressWarnings("unused")
public final class FbsPrincipalName extends Table {
  public static FbsPrincipalName getRootAsFbsPrincipalName(ByteBuffer _bb) { return getRootAsFbsPrincipalName(_bb, new FbsPrincipalName()); }
  public static FbsPrincipalName getRootAsFbsPrincipalName(ByteBuffer _bb, FbsPrincipalName obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__init(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public FbsPrincipalName __init(int _i, ByteBuffer _bb) { bb_pos = _i; bb = _bb; return this; }

  public int nameType() { int o = __offset(4); return o != 0 ? bb.getInt(o + bb_pos) : 0; }
  public boolean mutateNameType(int nameType) { int o = __offset(4); if (o != 0) { bb.putInt(o + bb_pos, nameType); return true; } else { return false; } }
  public String nameString() { int o = __offset(6); return o != 0 ? __string(o + bb_pos) : null; }
  public ByteBuffer nameStringAsByteBuffer() { return __vector_as_bytebuffer(6, 1); }

  public static int createFbsPrincipalName(FlatBufferBuilder builder,
      int nameType,
      int nameString) {
    builder.startObject(2);
    FbsPrincipalName.addNameString(builder, nameString);
    FbsPrincipalName.addNameType(builder, nameType);
    return FbsPrincipalName.endFbsPrincipalName(builder);
  }

  public static void startFbsPrincipalName(FlatBufferBuilder builder) { builder.startObject(2); }
  public static void addNameType(FlatBufferBuilder builder, int nameType) { builder.addInt(0, nameType, 0); }
  public static void addNameString(FlatBufferBuilder builder, int nameStringOffset) { builder.addOffset(1, nameStringOffset, 0); }
  public static int endFbsPrincipalName(FlatBufferBuilder builder) {
    int o = builder.endObject();
    return o;
  }
};

