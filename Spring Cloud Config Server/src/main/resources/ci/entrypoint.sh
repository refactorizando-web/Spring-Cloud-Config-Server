#!/bin/bash

source /data/stratio/kms_utils.sh
source /data/stratio/b-log.sh

MODULE_LOG_LEVEL=${MODULE_LOG_LEVEL:-"DEBUG"}
eval LOG_LEVEL_${MODULE_LOG_LEVEL}
B_LOG --stdout true # enable logging over stdout

export PORT_APP=${PORT_APP:-"8080"}

declare -a VAULT_HOSTS
IFS_OLD=$IFS
IFS=',' read -r -a VAULT_HOSTS <<< "$VAULT_HOST"

declare -a MARATHON_ARRAY
IFS='/' read -r -a MARATHON_ARRAY <<< "$MARATHON_APP_ID"

SERVICE_NAME=${MARATHON_ARRAY[-1]}
SERVICE_NAME_UNDERSCORE=${SERVICE_NAME//-/_}
SERVICE_NAME_UPPERCASE=${SERVICE_NAME_UNDERSCORE^^}

# Approle login from role_id, secret_id
INFO "Trying to login in Vault"
if [ "xxx$VAULT_TOKEN" == "xxx" ];
then
    INFO "Login in vault..."
    login
    if [[ ${code} -ne 0 ]];
    then
        ERROR "Something went wrong log in in vault. Exiting..."
        return ${code}
    fi
fi
INFO "  - Logged!"

#### Truststore ####

INFO "Getting ca-bundle"
getCAbundle "/data/stratio" "PEM" \
&& INFO "OK: ca-bundle downloaded"

getPass "userland" \
      ${SERVICE_NAME} \
      "truststore" \
      "pass"

CONFIG_SERVER_TRUSTSTORE_VAR=${SERVICE_NAME_UPPERCASE}_TRUSTSTORE_PASS

export SERVER_SSL_TRUST_STORE_PASSWORD=${!CONFIG_SERVER_TRUSTSTORE_VAR}

mkdir -p $JAVA_HOME/lib/security
keytool -importcert -file /data/stratio/ca-bundle.pem -noprompt -keystore cacerts -storepass ${SERVER_SSL_TRUST_STORE_PASSWORD} -alias ca

#### Server certificate ####

getCert "userland" \
       ${SERVICE_NAME} \
       ${SERVICE_NAME} \
        "JKS" \
        "/data/stratio" \
&& echo "OK: Getting ${SERVICE_NAME} certificate"   \
||  echo "Error: Getting ${SERVICE_NAME} certificate"

CONFIG_SERVER_KEYSTORE_PASSWORD_VAR=${SERVICE_NAME_UPPERCASE}_KEYSTORE_PASS
CONFIG_SERVER_KEYSTORE=/data/stratio/${SERVICE_NAME}.jks
export SERVER_SSL_KEY_STORE=${CONFIG_SERVER_KEYSTORE}
export SERVER_SSL_KEY_STORE_PASSWORD=${!CONFIG_SERVER_KEYSTORE_PASSWORD_VAR}
export SERVER_SSL_KEY_ALIAS=1
export SERVER_SSL_KEY_PASSWORD=${!CONFIG_SERVER_KEYSTORE_PASSWORD_VAR}

#### Git repository username and password #######

getPass userland ${SERVICE_NAME} git

GIT_USER_VAR=${SERVICE_NAME_UPPERCASE}_GIT_USER
GIT_PASS_VAR=${SERVICE_NAME_UPPERCASE}_GIT_PASS
export GIT_USERNAME=${!GIT_USER_VAR}
export GIT_PASSWORD=${!GIT_PASS_VAR}

### Kafka Authentication ####

getCert "userland" \
        "/gts/onboardings/${MARATHON_SERVICE_NAME}.onboardings.gts" \
        "${MARATHON_SERVICE_NAME}_onboardings_gts" \
        "JKS" \
        "/etc/stratio" \
    && INFO "OK"   \
    ||  INFO "Error"

CERTIFICATE_VAR_PASS=${MARATHON_SERVICE_NAME//-/_}"_onboardings_gts_keystore"
CERTIFICATE_VAR_PASS=${CERTIFICATE_VAR_PASS^^}
export CERTIFICATE_KEYSTORE_PASSWORD_VARIABLE=${!CERTIFICATE_VAR_PASS}
export SPRING_KAFKA_SSL_KEYSTORE_PASSWORD=${CERTIFICATE_KEYSTORE_PASSWORD_VARIABLE}
export SPRING_KAFKA_SSL_KEYPASSWORD=${CERTIFICATE_KEYSTORE_PASSWORD_VARIABLE}
export SPRING_KAFKA_PROPERTIES_SSL_KEYSTORE_LOCATION=/etc/stratio/kafka.pkcs12
export SPRING_KAFKA_PROPERTIES_SSL_KEYSTORE_TYPE=PKCS12
export SPRING_KAFKA_PROPERTIES_SECURITY_PROTOCOL=SSL

openssl pkcs12 -export -out /etc/stratio/kafka.pkcs12 \
-in /etc/stratio/"${MARATHON_SERVICE_NAME}_onboardings_gts".pem \
-inkey /etc/stratio/"${MARATHON_SERVICE_NAME}_onboardings_gts".key \
-passout pass:${SPRING_KAFKA_SSL_KEYSTORE_PASSWORD}



getCAbundle "/data/resources" "PEM" \
 && INFO "OK: Getting ca-bundle" \
 || INFO "Error: Getting ca-bundle"

${JAVA_HOME}/bin/keytool -noprompt -import -storepass changeit -file /data/resources/ca-bundle.pem -cacerts -alias ca

export SPRING_KAFKA_PROPERTIES_SSL_TRUSTSTORE_LOCATION=$JAVA_HOME/lib/security/cacerts
export SPRING_KAFKA_SSL_TRUSTSTORE_PASSWORD=changeit

#### Get/Generate Key for encrypting secrets

ENCRYPT_KEYS_ACTIVE=${ENCRYPT_KEYS_ACTIVE:-false}
if $ENCRYPT_KEYS_ACTIVE;
then
  getPass userland ${SERVICE_NAME} encryptkey
  ENCRYPTKEY_PASS_VAR=${SERVICE_NAME_UPPERCASE}_ENCRYPTKEY_PASS

  export ENCRYPT_KEY_STORE_LOCATION=${CONFIG_SERVER_KEYSTORE}
  export ENCRYPT_KEY_STORE_PASSWORD=${!CONFIG_SERVER_KEYSTORE_PASSWORD_VAR}
  export ENCRYPT_KEY_STORE_ALIAS=config-server-key
  export ENCRYPT_KEY_STORE_SECRET=${!ENCRYPTKEY_PASS_VAR}

  # Get from Vault
  INFO 'Getting encryption key from Vault.'
  KEY_FILE=/data/stratio/encrypt.key
  curl -fkL -s -XGET -H "X-Vault-Token:${VAULT_TOKEN}" https://${VAULT_HOST}:${VAULT_PORT}/v1/userland/extra/config-server/encryptkey -o ${KEY_FILE}.tmp
  if [ $? != 0 ];
  then
      INFO 'Encryption key does not exist. Generating it.'
      # Generate key pair
      keytool -keystore ${ENCRYPT_KEY_STORE_LOCATION} -storepass ${ENCRYPT_KEY_STORE_PASSWORD} -keypass ${ENCRYPT_KEY_STORE_SECRET} -alias ${ENCRYPT_KEY_STORE_ALIAS} \
          -genkeypair -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -dname "CN=Config Server,OU=TAM,O=Stratio"
      # Export to Vault
      keytool -export -keystore ${ENCRYPT_KEY_STORE_LOCATION} -storepass ${ENCRYPT_KEY_STORE_PASSWORD} -keypass ${ENCRYPT_KEY_STORE_SECRET} -alias ${ENCRYPT_KEY_STORE_ALIAS} -file ${KEY_FILE}
      KEY_B64="$(base64 ${KEY_FILE} | tr -d '[[:space:]]')"
      DEBUG 'Storing Encryption key in Vault.'
      curl -fkL -s -XPOST -H "X-Vault-Token:${VAULT_TOKEN}" -H "Content-Type: application/json" -d '{"encrypt_key":"'${KEY_B64}'"}' https://${VAULT_HOST}:${VAULT_PORT}/v1/userland/extra/config-server/encryptkey
  else
      DEBUG 'Loading encryption key in the Keystore.'
      cat ${KEY_FILE}.tmp | jq '.data.encrypt_key' | sed -e 's/^"//' -e 's/"$//'| base64 -d > ${KEY_FILE}
      keytool -keystore ${CONFIG_SERVER_KEYSTORE} -storepass ${ENCRYPT_KEY_STORE_PASSWORD} -keypass ${ENCRYPT_KEY_STORE_SECRET} -alias ${ENCRYPT_KEY_STORE_ALIAS} \
          -noprompt -importcert -file "${KEY_FILE}"
  fi
fi

#### Run Config-Server ####
HEAP_PERCENTAGE=${HEAP_PERCENTAGE:-"80"}
JAVA_TOOL_OPTIONS=${JAVA_TOOL_OPTIONS:-"-XX:+UseG1GC -XX:MaxRAMPercentage=${HEAP_PERCENTAGE} -XshowSettings:vm"}
java ${JAVA_TOOL_OPTIONS} -jar /data/app.jar ${JAVA_ARGS}