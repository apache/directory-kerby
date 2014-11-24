#/bin/bash
export TARGET_DIR=/home/julius/dev/commons-ssl/samples/pbe/openssl
export OPENSSL_APP='/home/julius/dev/commons-ssl/t/openssl-0.9.8e/apps/openssl'

export CIPHERS='
aes-128-cbc
aes-128-cfb
aes-128-cfb1
aes-128-cfb8
aes-128-ecb
aes-128-ofb
aes-192-cbc
aes-192-cfb
aes-192-cfb1
aes-192-cfb8
aes-192-ecb
aes-192-ofb
aes-256-cbc
aes-256-cfb
aes-256-cfb1
aes-256-cfb8
aes-256-ecb
aes-256-ofb
aes128
aes192
aes256
bf
bf-cbc
bf-cfb
bf-ecb
bf-ofb
blowfish
camellia-128-cbc
camellia-128-cfb
camellia-128-cfb1
camellia-128-cfb8
camellia-128-ecb
camellia-128-ofb
camellia-192-cbc
camellia-192-cfb
camellia-192-cfb1
camellia-192-cfb8
camellia-192-ecb
camellia-192-ofb
camellia-256-cbc
camellia-256-cfb
camellia-256-cfb1
camellia-256-cfb8
camellia-256-ecb
camellia-256-ofb
camellia128
camellia192
camellia256
cast
cast-cbc
cast5-cbc
cast5-cfb
cast5-ecb
cast5-ofb
des
des-cbc
des-cfb
des-cfb1
des-cfb8
des-ecb
des-ofb
des-ede
des-ede-cbc
des-ede-cfb
des-ede-ofb
des-ede3
des-ede3-cbc
des-ede3-cfb
des-ede3-ofb
des3
idea
idea-cbc
idea-cfb
idea-ecb
idea-ofb
rc2
rc2-40-cbc
rc2-64-cbc
rc2-cbc
rc2-cfb
rc2-ecb
rc2-ofb
rc4
rc4-40
rc5
rc5-cbc
rc5-cfb
rc5-ecb
rc5-ofb'

for CIPHER in $CIPHERS
do
  export OPENSSL_YES_B64_CMD="$OPENSSL_APP enc -$CIPHER -pass pass:changeit -a"
  export OPENSSL_NO_B64_CMD="$OPENSSL_APP enc -$CIPHER -pass pass:changeit"
  echo -n "Hello World!" | $OPENSSL_YES_B64_CMD > $TARGET_DIR/$CIPHER.base64
  echo -n "Hello World!" | $OPENSSL_NO_B64_CMD > $TARGET_DIR/$CIPHER.raw
done

# Not supported by any JSSE implementation I have access to:
#   desx
#   desx-cbc
