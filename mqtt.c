// MQTT Library (framework only)
// Jason Losh

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: -
// Target uC:       -
// System Clock:    -

// Hardware configuration:
// -

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "mqtt.h"
#include "tcp.h"
#include "timer.h"

// ------------------------------------------------------------------------------
// MQTT constants
// ------------------------------------------------------------------------------
#define MQTT_PORT              1883
#define MQTT_LOCAL_PORT        40000
#define MQTT_TX_BUFFER_SIZE    256
#define MQTT_KEEPALIVE_SEC     60

// MQTT packet types (upper nibble of first byte)
#define MQTT_PKT_CONNECT       1
#define MQTT_PKT_CONNACK       2
#define MQTT_PKT_PUBLISH       3
#define MQTT_PKT_PUBACK        4
#define MQTT_PKT_SUBSCRIBE     8
#define MQTT_PKT_SUBACK        9
#define MQTT_PKT_UNSUBSCRIBE   10
#define MQTT_PKT_UNSUBACK      11
#define MQTT_PKT_PINGREQ       12
#define MQTT_PKT_PINGRESP      13
#define MQTT_PKT_DISCONNECT    14

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------

// Change this to your Mosquitto broker IP
static uint8_t mqttBrokerIp[4] = {192, 168, 1, 100};

// MQTT/TCP connection state
static socket *mqttSocket = NULL;
static bool mqttTcpStarted = false;
static bool mqttConnectSent = false;
static bool mqttConnected = false;

// MQTT packet identifier (used by SUBSCRIBE/UNSUBSCRIBE)
static uint16_t mqttPacketId = 1;

// MQTT client id used in CONNECT
static char mqttClientId[] = "TM4C";

// Last received control command for lock project
// 0 = none, 1 = LOCK, 2 = UNLOCK
volatile uint8_t mqttLastCommand = 0;

// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------
// ------------------------------------------------------------------------------
// Local helpers
// ------------------------------------------------------------------------------

/*
 * Encodes MQTT Remaining Length field.
 *
 * MQTT uses a variable-length encoding for Remaining Length.
 * Your notes show this field can be 1 to 4 bytes and is encoded
 * least-significant 7 bits first, with bit 7 meaning "continue." :contentReference[oaicite:3]{index=3}
 *
 * Returns number of bytes written.
 */
static uint8_t encodeRemainingLength(uint8_t *buf, uint16_t length)
{
    uint8_t count = 0;

    do
    {
        uint8_t digit = length % 128;
        length /= 128;

        if (length > 0)
            digit |= 0x80;

        buf[count++] = digit;
    }
    while (length > 0);

    return count;
}

/*
 * Writes a UTF-8 style MQTT string:
 * 2-byte MSB-first length + raw bytes.
 *
 * Used for:
 * - protocol name
 * - client ID
 * - topic strings
 *
 * Returns new write index.
 */
static uint16_t writeMqttString(uint8_t *buf, uint16_t index, char str[])
{
    uint16_t len = strlen(str);

    buf[index++] = (len >> 8) & 0xFF;
    buf[index++] = len & 0xFF;

    memcpy(&buf[index], str, len);
    index += len;

    return index;
}

/*
 * Builds and sends MQTT CONNECT once TCP is established.
 *
 * CONNECT packet format from your notes:
 * Fixed header
 * Variable header:
 *   Protocol Name = "MQTT"
 *   Protocol Level = 4
 *   Connect Flags
 *   Keep Alive
 * Payload:
 *   Client ID
 * :contentReference[oaicite:4]{index=4}
 */
static void sendMqttConnectPacket(void)
{
    uint8_t buf[MQTT_TX_BUFFER_SIZE];
    uint16_t index = 0;
    uint16_t remStart;
    uint16_t remLength;
    uint8_t remEncoded[4];
    uint8_t remBytes;
    uint16_t payloadStart;
    uint16_t totalLen;

    if (mqttSocket == NULL)
        return;

    if (!tcpIsConnected(mqttSocket))
        return;

    // Fixed header byte 1: CONNECT (0001) with required flags 0000
    buf[index++] = 0x10;

    // Reserve space conceptually for Remaining Length; we will insert it later
    remStart = index;
    index += 4;   // temporary room, we'll compact after encoding

    // ---------------------------
    // Variable header
    // ---------------------------
    index = writeMqttString(buf, index, "MQTT");  // protocol name
    buf[index++] = 0x04;                          // protocol level = 4 (MQTT 3.1.1)
    buf[index++] = 0x02;                          // clean session flag
    buf[index++] = 0x00;                          // keep alive MSB
    buf[index++] = MQTT_KEEPALIVE_SEC;            // keep alive LSB

    // ---------------------------
    // Payload
    // ---------------------------
    payloadStart = index;
    index = writeMqttString(buf, index, mqttClientId);

    // Remaining length = variable header + payload
    remLength = index - (remStart + 4);

    // Encode remaining length into minimal number of bytes
    remBytes = encodeRemainingLength(remEncoded, remLength);

    // Move variable header + payload left if fewer than 4 bytes used
    memmove(&buf[1 + remBytes], &buf[remStart + 4], remLength);

    // Copy encoded Remaining Length bytes
    memcpy(&buf[1], remEncoded, remBytes);

    totalLen = 1 + remBytes + remLength;

    if (tcpSend(mqttSocket, buf, totalLen))
        mqttConnectSent = true;
}

/*
 * Starts the TCP connection if needed and then sends MQTT CONNECT
 * once TCP enters ESTABLISHED.
 *
 * Because your connectMqtt() API has no parameters and no return value,
 * this helper lets connectMqtt() be called more than once safely.
 */
static void mqttConnectionStep(void)
{
    if (mqttSocket == NULL && !mqttTcpStarted)
    {
        mqttSocket = tcpConnect(mqttBrokerIp, MQTT_PORT, MQTT_LOCAL_PORT);
        if (mqttSocket != NULL)
            mqttTcpStarted = true;
        return;
    }

    if (mqttSocket != NULL && tcpIsConnected(mqttSocket) && !mqttConnectSent)
    {
        sendMqttConnectPacket();
    }
}
//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

/*
 * Starts MQTT connection process.
 *
 * First call:
 * - starts TCP active open to broker
 *
 * Later calls:
 * - once TCP is established, sends MQTT CONNECT
 *
 * After broker replies CONNACK, processMqttMessage() will set mqttConnected=true.
 */
void connectMqtt()
{
    mqttConnectionStep();
}

/*
 * Sends MQTT DISCONNECT and then closes TCP.
 *
 * DISCONNECT packet:
 * fixed header only, no variable header, no payload. :contentReference[oaicite:5]{index=5}
 */
void disconnectMqtt()
{
    uint8_t buf[2];

    if (mqttSocket == NULL)
        return;

    if (!tcpIsConnected(mqttSocket))
        return;

    buf[0] = 0xE0;   // DISCONNECT
    buf[1] = 0x00;   // Remaining Length = 0

    tcpSend(mqttSocket, buf, 2);
    tcpClose(mqttSocket);

    mqttConnected = false;
    mqttConnectSent = false;
    mqttTcpStarted = false;
    mqttSocket = NULL;
}

void publishMqtt(char strTopic[], char strData[])
{
    uint8_t buf[MQTT_TX_BUFFER_SIZE];
    uint16_t index = 0;
    uint16_t topicLen = strlen(strTopic);
    uint16_t dataLen = strlen(strData);
    uint16_t remLength;
    uint8_t remEncoded[4];
    uint8_t remBytes;
    uint16_t totalLen;

    if (mqttSocket == NULL || !mqttConnected)
        return;

    // Fixed header: PUBLISH, DUP=0, QoS=0, RETAIN=0
    buf[index++] = 0x30;

    // Remaining length = topic string field + payload
    remLength = 2 + topicLen + dataLen;
    remBytes = encodeRemainingLength(remEncoded, remLength);
    memcpy(&buf[index], remEncoded, remBytes);
    index += remBytes;

    // Topic name
    buf[index++] = (topicLen >> 8) & 0xFF;
    buf[index++] = topicLen & 0xFF;
    memcpy(&buf[index], strTopic, topicLen);
    index += topicLen;

    // Payload
    memcpy(&buf[index], strData, dataLen);
    index += dataLen;

    totalLen = index;

    tcpSend(mqttSocket, buf, totalLen);
}

/*
 * Sends SUBSCRIBE for one topic at requested QoS 0.
 *
 * Your notes show SUBSCRIBE includes:
 * Fixed header,
 * Variable header = packet ID,
 * Payload = topic filter + requested QoS. :contentReference[oaicite:7]{index=7}
 */
void subscribeMqtt(char strTopic[])
{
    uint8_t buf[MQTT_TX_BUFFER_SIZE];
    uint16_t index = 0;
    uint16_t topicLen = strlen(strTopic);
    uint16_t remLength;
    uint8_t remEncoded[4];
    uint8_t remBytes;
    uint16_t totalLen;

    if (mqttSocket == NULL || !mqttConnected)
        return;

    // Fixed header: SUBSCRIBE requires flags 0010
    buf[index++] = 0x82;

    // Remaining length:
    // packet ID (2 bytes) + topic length field (2) + topic + requested QoS (1)
    remLength = 2 + 2 + topicLen + 1;
    remBytes = encodeRemainingLength(remEncoded, remLength);
    memcpy(&buf[index], remEncoded, remBytes);
    index += remBytes;

    // Packet identifier
    buf[index++] = (mqttPacketId >> 8) & 0xFF;
    buf[index++] = mqttPacketId & 0xFF;

    // Topic filter
    buf[index++] = (topicLen >> 8) & 0xFF;
    buf[index++] = topicLen & 0xFF;
    memcpy(&buf[index], strTopic, topicLen);
    index += topicLen;

    // Requested QoS = 0
    buf[index++] = 0x00;

    totalLen = index;
    tcpSend(mqttSocket, buf, totalLen);

    mqttPacketId++;
}

/*
 * Sends UNSUBSCRIBE for one topic.
 *
 * Your notes show UNSUBSCRIBE includes:
 * Fixed header,
 * Variable header = packet ID,
 * Payload = topic filter. :contentReference[oaicite:8]{index=8}
 */
void unsubscribeMqtt(char strTopic[])
{
    uint8_t buf[MQTT_TX_BUFFER_SIZE];
    uint16_t index = 0;
    uint16_t topicLen = strlen(strTopic);
    uint16_t remLength;
    uint8_t remEncoded[4];
    uint8_t remBytes;
    uint16_t totalLen;

    if (mqttSocket == NULL || !mqttConnected)
        return;

    // Fixed header: UNSUBSCRIBE requires flags 0010
    buf[index++] = 0xA2;

    // Remaining length:
    // packet ID (2 bytes) + topic length field (2) + topic
    remLength = 2 + 2 + topicLen;
    remBytes = encodeRemainingLength(remEncoded, remLength);
    memcpy(&buf[index], remEncoded, remBytes);
    index += remBytes;

    // Packet identifier
    buf[index++] = (mqttPacketId >> 8) & 0xFF;
    buf[index++] = mqttPacketId & 0xFF;

    // Topic filter
    buf[index++] = (topicLen >> 8) & 0xFF;
    buf[index++] = topicLen & 0xFF;
    memcpy(&buf[index], strTopic, topicLen);
    index += topicLen;

    totalLen = index;
    tcpSend(mqttSocket, buf, totalLen);

    mqttPacketId++;
}

// ------------------------------------------------------------------------------
// Receive-side helper
// ------------------------------------------------------------------------------

/*
 * Processes one incoming MQTT packet already extracted from TCP payload.
 *
 * This function is needed to:
 * - detect CONNACK and mark mqttConnected=true
 * - optionally react to SUBACK / UNSUBACK
 * - decode incoming PUBLISH commands such as LOCK / UNLOCK
 *
 * Packet types from notes:
 * CONNACK = 2, PUBLISH = 3, SUBACK = 9, UNSUBACK = 11, etc. :contentReference[oaicite:9]{index=9}
 */
void processMqttMessage(uint8_t data[], uint16_t length)
{
    uint8_t packetType;
    uint16_t topicLen;
    uint16_t index;
    uint16_t payloadLen;
    char topic[64];
    char payload[64];

    if (data == NULL || length < 2)
        return;

    packetType = (data[0] >> 4) & 0x0F;

    switch (packetType)
    {
        case MQTT_PKT_CONNACK:
        {
            // CONNACK variable header is 2 bytes:
            // [session present][return code]
            // Accepted return code is 0 according to your notes. :contentReference[oaicite:10]{index=10}
            if (length >= 4 && data[3] == 0x00)
                mqttConnected = true;
            break;
        }

        case MQTT_PKT_SUBACK:
        {
            // Minimal implementation: nothing required here
            break;
        }

        case MQTT_PKT_UNSUBACK:
        {
            // Minimal implementation: nothing required here
            break;
        }

        case MQTT_PKT_PUBLISH:
        {
            // QoS 0 PUBLISH parsing:
            // byte 0 = header
            // byte 1..n = remaining length
            // then topic length + topic + payload
            //
            // For simplicity here, assume Remaining Length fits in 1 byte.
            if (length < 4)
                return;

            index = 2;  // start after fixed header + 1-byte remaining length

            topicLen = ((uint16_t)data[index] << 8) | data[index + 1];
            index += 2;

            if (topicLen >= sizeof(topic))
                return;

            if ((index + topicLen) > length)
                return;

            memcpy(topic, &data[index], topicLen);
            topic[topicLen] = 0;
            index += topicLen;

            payloadLen = length - index;
            if (payloadLen >= sizeof(payload))
                payloadLen = sizeof(payload) - 1;

            memcpy(payload, &data[index], payloadLen);
            payload[payloadLen] = 0;

            // Example project command topic
            if (strcmp(topic, "lock/control") == 0)
            {
                if (strcmp(payload, "LOCK") == 0)
                    mqttLastCommand = 1;
                else if (strcmp(payload, "UNLOCK") == 0)
                    mqttLastCommand = 2;
            }

            break;
        }

        default:
            break;
    }
}
