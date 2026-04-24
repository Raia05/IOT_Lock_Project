// MQTT Library
// Jason Losh

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "mqtt.h"
#include "tcp.h"
#include "ip.h"
#include "uart0.h"
#include "timer.h"

// ------------------------------------------------------------------------------
// Globals
// ------------------------------------------------------------------------------

static socket *mqttSocket = 0;
static bool mqttConnectRequested = false;
static bool mqttConnectSent = false;
static bool mqttConnected = false;

static uint16_t mqttBrokerPort = 1883;
static uint16_t mqttLocalPort = 50001;
static char mqttClientId[] = "lock";

static uint32_t mqttPingTimer = 0;
static bool mqttPingWaiting = false;
#define MQTT_KEEPALIVE_SECONDS 60
#define MQTT_PING_INTERVAL_SECONDS 30

// ------------------------------------------------------------------------------
// Local helpers
// ------------------------------------------------------------------------------

static uint16_t mqttAddString(uint8_t *buffer, uint16_t index, char str[])
{
    uint16_t len = strlen(str);

    buffer[index++] = (len >> 8) & 0xFF;
    buffer[index++] = len & 0xFF;
    memcpy(&buffer[index], str, len);
    index += len;

    return index;
}

static uint16_t mqttEncodeRemainingLength(uint8_t *buffer, uint16_t length)
{
    uint16_t count = 0;
    uint8_t encodedByte;

    do
    {
        encodedByte = length % 128;
        length /= 128;

        if (length > 0)
            encodedByte |= 0x80;

        buffer[count++] = encodedByte;
    }
    while (length > 0);

    return count;
}

static bool mqttSendSimplePacket(uint8_t packetType)
{
    uint8_t packet[2];

    if (mqttSocket == 0)
        return false;

    packet[0] = packetType;
    packet[1] = 0x00;

    return tcpSend(mqttSocket, packet, 2);
}

static bool mqttSendConnectPacket(void)
{
    uint8_t packet[128];
    uint16_t i = 0;
    uint16_t remainingLength;
    uint16_t rlBytes;

    if (mqttSocket == 0)
        return false;

    packet[i++] = 0x10;   // CONNECT

    remainingLength = 10 + 2 + strlen(mqttClientId);
    rlBytes = mqttEncodeRemainingLength(&packet[i], remainingLength);
    i += rlBytes;

    // Variable header
    packet[i++] = 0x00;
    packet[i++] = 0x04;
    packet[i++] = 'M';
    packet[i++] = 'Q';
    packet[i++] = 'T';
    packet[i++] = 'T';
    packet[i++] = 0x04;   // MQTT 3.1.1
    packet[i++] = 0x02;   // Clean Session
    packet[i++] = 0x00;   // Keepalive MSB
    packet[i++] = 0x3C;   // Keepalive LSB = 60

    // Payload
    i = mqttAddString(packet, i, mqttClientId);

    return tcpSend(mqttSocket, packet, i);
}

void callbackMqttPingTimer(void)
{
    mqttPingTimer++;
}

void processMqttKeepAlive(void)
{
    if (mqttSocket == 0)
        return;

    if (!mqttConnected)
        return;

    if (!tcpIsConnected(mqttSocket))
        return;

    if (mqttPingTimer >= MQTT_PING_INTERVAL_SECONDS)
    {
        mqttSendSimplePacket(0xC0);   // PINGREQ
        mqttPingTimer = 0;
        mqttPingWaiting = true;
        //putsUart0("MQTT PINGREQ sent\r\n");
    }
}

void processMqttResponse(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint8_t tcpHeaderLength;
    uint16_t ipTotalLength;
    uint16_t tcpSegmentLength;
    uint16_t payloadLength;
    uint8_t *payload;
    uint8_t packetType;
    uint8_t returnCode;
    uint16_t topicLength;
    uint16_t originalTopicLength;
    uint16_t topicIndex;
    uint16_t dataIndex;
    uint16_t dataLength;
    char topic[64];
    char msg[128];
    uint16_t i;

    if (mqttSocket == 0)
        return;

    if (!isTcp(ether))
        return;

    if (!tcpIsConnected(mqttSocket))
        return;

    ip = (ipHeader*) ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*) ((uint8_t*) ip + ipHeaderLength);
    tcpHeaderLength = (ntohs(tcp->offsetFields) >> OFS_SHIFT) * 4;

    ipTotalLength = ntohs(ip->length);
    tcpSegmentLength = ipTotalLength - ipHeaderLength;

    if (tcpSegmentLength < tcpHeaderLength)
        return;

    payloadLength = tcpSegmentLength - tcpHeaderLength;

    if (payloadLength == 0)
        return;

    payload = (uint8_t*) tcp + tcpHeaderLength;
    packetType = payload[0] & 0xF0;

    // Any valid MQTT packet from broker means connection is alive
    mqttPingTimer = 0;

    // CONNACK
    if (packetType == 0x20)
    {
        if (payloadLength >= 4 && payload[1] == 0x02)
        {
            returnCode = payload[3];

            if (returnCode == 0x00)
            {
                mqttConnected = true;
                mqttPingWaiting = false;
                mqttPingTimer = 0;

                startPeriodicTimer(callbackMqttPingTimer, 1);

                putsUart0("MQTT CONNACK accepted\r\n");
            }
            else
            {
                mqttConnected = false;
                putsUart0("MQTT CONNACK rejected\r\n");
            }
        }
    }
    // PINGRESP
    else if (packetType == 0xD0)
    {
        mqttPingWaiting = false;
        //putsUart0("MQTT PINGRESP received\r\n");
    }
    // SUBACK
    else if (packetType == 0x90)
    {
        putsUart0("MQTT SUBACK received\r\n");
    }
    // UNSUBACK
    else if (packetType == 0xB0)
    {
        putsUart0("MQTT UNSUBACK received\r\n");
    }
    // PUBLISH from broker, QoS 0 only
    else if (packetType == 0x30)
    {
        if (payloadLength < 4)
            return;

        originalTopicLength = ((uint16_t)payload[2] << 8) | payload[3];
        topicLength = originalTopicLength;
        topicIndex = 4;

        if ((topicIndex + originalTopicLength) > payloadLength)
            return;

        if (topicLength >= sizeof(topic))
            topicLength = sizeof(topic) - 1;

        for (i = 0; i < topicLength; i++)
            topic[i] = payload[topicIndex + i];
        topic[topicLength] = '\0';

        dataIndex = 4 + originalTopicLength;

        if (dataIndex > payloadLength)
            return;

        dataLength = payloadLength - dataIndex;

        if (dataLength >= sizeof(msg))
            dataLength = sizeof(msg) - 1;

        for (i = 0; i < dataLength; i++)
            msg[i] = payload[dataIndex + i];
        msg[dataLength] = '\0';

        putsUart0("MQTT PUBLISH received\r\n");
        putsUart0("  topic: ");
        putsUart0(topic);
        putsUart0("\r\n");
        putsUart0("  data: ");
        putsUart0(msg);
        putsUart0("\r\n");
    }
}


// ------------------------------------------------------------------------------
// Public functions
// ------------------------------------------------------------------------------

void connectMqtt()
{
    uint8_t brokerIp[4];

    getIpMqttBrokerAddress(brokerIp);

    mqttConnectRequested = true;
    mqttConnectSent = false;
    mqttConnected = false;

    if (mqttSocket == 0)
        mqttSocket = tcpConnect(brokerIp, mqttBrokerPort, mqttLocalPort);

    if (mqttSocket != 0)
        putsUart0("MQTT TCP connect requested\r\n");
    else
        putsUart0("MQTT TCP connect failed\r\n");
}

void disconnectMqtt()
{
    if (mqttSocket == 0)
    {
        putsUart0("MQTT not connected\r\n");
        return;
    }

    if (tcpIsConnected(mqttSocket))
    {
        mqttSendSimplePacket(0xE0);   // MQTT DISCONNECT
        tcpClose(mqttSocket);         // queue TCP FIN
        putsUart0("MQTT disconnect requested\r\n");
    }
    else
    {
        mqttSocket = 0;
        mqttConnectRequested = false;
        mqttConnectSent = false;
        mqttConnected = false;
        putsUart0("MQTT socket cleared\r\n");
    }
}

void processMqttConnection()
{
    if (mqttSocket != 0)
    {
        if (mqttSocket->state == TCP_CLOSED || mqttSocket->state == TCP_TIME_WAIT)
        {
            mqttSocket = 0;
            mqttConnectRequested = false;
            mqttConnectSent = false;
            mqttConnected = false;
            putsUart0("MQTT socket closed\r\n");
            return;
        }
    }

    if (!mqttConnectRequested)
        return;

    if (mqttSocket == 0)
        return;

    if (tcpIsConnected(mqttSocket) && !mqttConnectSent)
    {
        if (mqttSendConnectPacket())
        {
            mqttConnectSent = true;
            putsUart0("MQTT CONNECT sent\r\n");
        }
    }
}

void publishMqtt(char strTopic[], char strData[])
{
    uint8_t packet[256];
    uint16_t i = 0;
    uint16_t topicLen;
    uint16_t dataLen;
    uint16_t remainingLength;
    uint16_t rlBytes;

    if (mqttSocket == 0 || !mqttConnected || !tcpIsConnected(mqttSocket))
    {
        putsUart0("MQTT not connected\r\n");
        return;
    }

    topicLen = strlen(strTopic);
    dataLen = strlen(strData);

    packet[i++] = 0x30;   // PUBLISH QoS0

    remainingLength = 2 + topicLen + dataLen;
    rlBytes = mqttEncodeRemainingLength(&packet[i], remainingLength);
    i += rlBytes;

    i = mqttAddString(packet, i, strTopic);

    memcpy(&packet[i], strData, dataLen);
    i += dataLen;

    if (tcpSend(mqttSocket, packet, i))
    {
        mqttPingTimer = 0;
        putsUart0("MQTT PUBLISH sent\r\n");
    }
}

void subscribeMqtt(char strTopic[])
{
    uint8_t packet[256];
    uint16_t i = 0;
    uint16_t topicLen;
    uint16_t remainingLength;
    uint16_t rlBytes;
    static uint16_t packetId = 1;

    if (mqttSocket == 0 || !mqttConnected || !tcpIsConnected(mqttSocket))
    {
        putsUart0("MQTT not connected\r\n");
        return;
    }

    topicLen = strlen(strTopic);

    packet[i++] = 0x82;   // SUBSCRIBE

    remainingLength = 2 + 2 + topicLen + 1;
    rlBytes = mqttEncodeRemainingLength(&packet[i], remainingLength);
    i += rlBytes;

    packet[i++] = (packetId >> 8) & 0xFF;
    packet[i++] = packetId & 0xFF;

    i = mqttAddString(packet, i, strTopic);
    packet[i++] = 0x00;   // QoS 0

    packetId++;

    if (tcpSend(mqttSocket, packet, i))
    {
        mqttPingTimer = 0;
        putsUart0("MQTT SUBSCRIBE sent\r\n");
    }
}

void unsubscribeMqtt(char strTopic[])
{
    uint8_t packet[256];
    uint16_t i = 0;
    uint16_t topicLen;
    uint16_t remainingLength;
    uint16_t rlBytes;
    static uint16_t packetId = 100;

    if (mqttSocket == 0 || !mqttConnected || !tcpIsConnected(mqttSocket))
    {
        putsUart0("MQTT not connected\r\n");
        return;
    }

    topicLen = strlen(strTopic);

    packet[i++] = 0xA2;   // UNSUBSCRIBE

    remainingLength = 2 + 2 + topicLen;
    rlBytes = mqttEncodeRemainingLength(&packet[i], remainingLength);
    i += rlBytes;

    packet[i++] = (packetId >> 8) & 0xFF;
    packet[i++] = packetId & 0xFF;

    i = mqttAddString(packet, i, strTopic);

    packetId++;

    if (tcpSend(mqttSocket, packet, i))
    {
        mqttPingTimer = 0;
        putsUart0("MQTT UNSUBSCRIBE sent\r\n");
    }
}
