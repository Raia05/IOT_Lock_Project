// MQTT Library
// Jason Losh

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "mqtt.h"
#include "tcp.h"
#include "timer.h"
#include "uart0.h"

// ------------------------------------------------------------------------------
// Globals
// ------------------------------------------------------------------------------

static socket *mqttSocket = 0;
static bool mqttConnectRequested = false;
static bool mqttConnectSent = false;
static bool mqttConnected = false;

static uint8_t mqttBrokerIp[4] = {192, 168, 1, 51};   // CHANGE THIS IF NEEDED
static uint16_t mqttBrokerPort = 1883;
static uint16_t mqttLocalPort = 50000;

static char mqttClientId[] = "tm4cClient";

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
    packet[i++] = 0x02;   // Clean session
    packet[i++] = 0x00;   // Keep alive MSB
    packet[i++] = 0x3C;   // Keep alive LSB = 60

    // Payload
    i = mqttAddString(packet, i, mqttClientId);

    return tcpSend(mqttSocket, packet, i);
}

// ------------------------------------------------------------------------------
// Public functions
// ------------------------------------------------------------------------------

void connectMqtt()
{
    mqttConnectRequested = true;
    mqttConnectSent = false;
    mqttConnected = false;

    if (mqttSocket == 0)
    {
        mqttSocket = tcpConnect(mqttBrokerIp, mqttBrokerPort, mqttLocalPort);
    }

    if (mqttSocket != 0)
        putsUart0("MQTT TCP connect requested\r\n");
    else
        putsUart0("MQTT TCP connect failed\r\n");
}

void disconnectMqtt()
{
    if (mqttSocket != 0)
    {
        mqttSendSimplePacket(0xE0);   // DISCONNECT
        tcpClose(mqttSocket);
        mqttSocket = 0;
    }

    mqttConnectRequested = false;
    mqttConnectSent = false;
    mqttConnected = false;

    putsUart0("MQTT disconnect requested\r\n");
}

void processMqttConnection()
{
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

    if (mqttSocket == 0)
        return;

    topicLen = strlen(strTopic);
    dataLen = strlen(strData);

    packet[i++] = 0x30;   // PUBLISH QoS0

    remainingLength = 2 + topicLen + dataLen;
    rlBytes = mqttEncodeRemainingLength(&packet[i], remainingLength);
    i += rlBytes;

    i = mqttAddString(packet, i, strTopic);

    memcpy(&packet[i], strData, dataLen);
    i += dataLen;

    tcpSend(mqttSocket, packet, i);
    putsUart0("MQTT PUBLISH sent\r\n");
}

void subscribeMqtt(char strTopic[])
{
    uint8_t packet[256];
    uint16_t i = 0;
    uint16_t topicLen;
    uint16_t remainingLength;
    uint16_t rlBytes;
    static uint16_t packetId = 1;

    if (mqttSocket == 0)
        return;

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

    tcpSend(mqttSocket, packet, i);
    putsUart0("MQTT SUBSCRIBE sent\r\n");
}

void unsubscribeMqtt(char strTopic[])
{
    uint8_t packet[256];
    uint16_t i = 0;
    uint16_t topicLen;
    uint16_t remainingLength;
    uint16_t rlBytes;
    static uint16_t packetId = 100;

    if (mqttSocket == 0)
        return;

    topicLen = strlen(strTopic);

    packet[i++] = 0xA2;   // UNSUBSCRIBE

    remainingLength = 2 + 2 + topicLen;
    rlBytes = mqttEncodeRemainingLength(&packet[i], remainingLength);
    i += rlBytes;

    packet[i++] = (packetId >> 8) & 0xFF;
    packet[i++] = packetId & 0xFF;

    i = mqttAddString(packet, i, strTopic);

    packetId++;

    tcpSend(mqttSocket, packet, i);
    putsUart0("MQTT UNSUBSCRIBE sent\r\n");
}
