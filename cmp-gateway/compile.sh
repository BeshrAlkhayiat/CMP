#!/bin/bash
# Compile script for CMP Gateway

set -e

GATEWAY_DIR="$(cd "$(dirname "$0")" && pwd)"
CMP_RA_COMPONENT_JAR="$GATEWAY_DIR/lib/CmpRaComponent-4.3.0.jar"
BCPROV_JAR="$GATEWAY_DIR/lib/bcprov-jdk18on-1.79.jar"
BCPKIX_JAR="$GATEWAY_DIR/lib/bcpkix-jdk18on-1.79.jar"
SLF4J_API_JAR="$GATEWAY_DIR/lib/slf4j-api-2.0.16.jar"
SLF4J_SIMPLE_JAR="$GATEWAY_DIR/lib/slf4j-simple-2.0.16.jar"
JACKSON_DATABIND_JAR="$GATEWAY_DIR/lib/jackson-databind-2.18.2.jar"
JACKSON_CORE_JAR="$GATEWAY_DIR/lib/jackson-core-2.18.2.jar"
JACKSON_ANNOTATIONS_JAR="$GATEWAY_DIR/lib/jackson-annotations-2.18.2.jar"

# Download dependencies if not present
if [ ! -f "$BCPROV_JAR" ]; then
    echo "Downloading Bouncy Castle..."
    curl -sL -o "$BCPROV_JAR" "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.79/bcprov-jdk18on-1.79.jar"
    curl -sL -o "$BCPKIX_JAR" "https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk18on/1.79/bcpkix-jdk18on-1.79.jar"
fi

if [ ! -f "$SLF4J_API_JAR" ]; then
    echo "Downloading SLF4J..."
    curl -sL -o "$SLF4J_API_JAR" "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar"
    curl -sL -o "$SLF4J_SIMPLE_JAR" "https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/2.0.16/slf4j-simple-2.0.16.jar"
fi

if [ ! -f "$JACKSON_DATABIND_JAR" ]; then
    echo "Downloading Jackson..."
    curl -sL -o "$JACKSON_DATABIND_JAR" "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.18.2/jackson-databind-2.18.2.jar"
    curl -sL -o "$JACKSON_CORE_JAR" "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.18.2/jackson-core-2.18.2.jar"
    curl -sL -o "$JACKSON_ANNOTATIONS_JAR" "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.18.2/jackson-annotations-2.18.2.jar"
fi

CLASSPATH="$CMP_RA_COMPONENT_JAR:$BCPROV_JAR:$BCPKIX_JAR:$SLF4J_API_JAR:$SLF4J_SIMPLE_JAR:$JACKSON_DATABIND_JAR:$JACKSON_CORE_JAR:$JACKSON_ANNOTATIONS_JAR"

echo "Compiling CMP Gateway..."
mkdir -p "$GATEWAY_DIR/build/classes"

javac -version
javac \
  -cp "$CLASSPATH" \
  -d "$GATEWAY_DIR/build/classes" \
  -source 17 \
  -target 17 \
  "$GATEWAY_DIR/src/main/java/com/siemens/pki/cmpgateway/Main.java" \
  "$GATEWAY_DIR/src/main/java/com/siemens/pki/cmpgateway/config/GatewayConfig.java" \
  "$GATEWAY_DIR/src/main/java/com/siemens/pki/cmpgateway/rest/RestClient.java" \
  "$GATEWAY_DIR/src/main/java/com/siemens/pki/cmpgateway/server/CmpGateway.java"

echo "Compilation successful!"
echo "Run with: java -cp \"$CLASSPATH:$GATEWAY_DIR/build/classes\" com.siemens.pki.cmpgateway.Main"
