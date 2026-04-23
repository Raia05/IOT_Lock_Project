// TCP Library
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
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "arp.h"
#include "dhcp.h"
#include "ip.h"
#include "socket.h"
#include "tcp.h"
#include "timer.h"
#include "uart0.h"

// ------------------------------------------------------------------------------
// Globals
// ------------------------------------------------------------------------------

#define MAX_TCP_SOCKETS 10
#define TCP_TX_BUFFER_SIZE 512

// Socket table comes from socket.c
extern socket sockets[MAX_TCP_SOCKETS];

// These are kept only because tcp.h already expects them.
uint16_t tcpPorts[MAX_TCP_PORTS];
uint8_t tcpPortCount = 0;
uint8_t tcpState[MAX_TCP_PORTS];

// Simple IP identification counter for outgoing IP packets
static uint16_t tcpIpId = 1;

// Per-socket flags used by the client-side connection flow
static bool tcpArpPending[MAX_TCP_SOCKETS];
static bool tcpSynPending[MAX_TCP_SOCKETS];
static bool tcpTxPending[MAX_TCP_SOCKETS];
static bool tcpFinPending[MAX_TCP_SOCKETS];

// Per-socket pending transmit buffer
static uint16_t tcpPendingTxSize[MAX_TCP_SOCKETS];
static uint8_t tcpPendingTxData[MAX_TCP_SOCKETS][TCP_TX_BUFFER_SIZE];

// one-shot connect test
//static bool tcpTestStarted = false;
//static socket *tcpTestSocket = 0;

// ------------------------------------------------------------------------------
// Local helpers
// ------------------------------------------------------------------------------

static uint8_t getSocketIndex(socket *s)
{
    return (uint8_t)(s - sockets);
}

static void clearTcpPendingState(uint8_t i)
{
    tcpArpPending[i] = false;
    tcpSynPending[i] = false;
    tcpTxPending[i] = false;
    tcpFinPending[i] = false;
    tcpPendingTxSize[i] = 0;
}

static uint8_t getTcpHeaderLengthBytes(tcpHeader *tcp)
{
    return (uint8_t)((ntohs(tcp->offsetFields) >> OFS_SHIFT) * 4);
}

static uint16_t getTcpFlags(tcpHeader *tcp)
{
    return (uint16_t)(ntohs(tcp->offsetFields) & 0x01FF);
}


static uint16_t getTcpPayloadLength(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint16_t tcpSegmentLength = ntohs(ip->length) - ipHeaderLength;
    uint16_t tcpHeaderLength = getTcpHeaderLengthBytes(tcp);

    if (tcpSegmentLength < tcpHeaderLength)
        return 0;

    return tcpSegmentLength - tcpHeaderLength;
}

static uint32_t tcpControlLength(tcpHeader *tcp, uint16_t payloadLength)
{
    uint16_t flags = getTcpFlags(tcp);
    uint32_t amount = payloadLength;

    if (flags & SYN) amount++;
    if (flags & FIN) amount++;

    return amount;
}

static void sumTcpPseudoHeader(ipHeader *ip, uint16_t tcpLength, uint32_t *sum)
{
    sumIpWords(ip->sourceIp, 4, sum);
    sumIpWords(ip->destIp, 4, sum);
    *sum += 0;
    *sum += PROTOCOL_TCP << 8;
    *sum += (tcpLength & 0x00FF) << 8;
    *sum += (tcpLength & 0xFF00) >> 8;
}

static uint16_t calcTcpChecksum(ipHeader *ip, tcpHeader *tcp, uint16_t tcpLength)
{
    uint32_t sum = 0;
    tcp->checksum = 0;
    sumTcpPseudoHeader(ip, tcpLength, &sum);
    sumIpWords(tcp, tcpLength, &sum);
    return getIpChecksum(sum);
}


static socket *findSocketByTuple(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint16_t srcPort = ntohs(tcp->sourcePort);
    uint16_t dstPort = ntohs(tcp->destPort);
    uint8_t i;

    for (i = 0; i < MAX_TCP_SOCKETS; i++)
    {
        if (sockets[i].localPort == dstPort &&
            sockets[i].remotePort == srcPort &&
            sockets[i].remoteIpAddress[0] == ip->sourceIp[0] &&
            sockets[i].remoteIpAddress[1] == ip->sourceIp[1] &&
            sockets[i].remoteIpAddress[2] == ip->sourceIp[2] &&
            sockets[i].remoteIpAddress[3] == ip->sourceIp[3])
        {
            return &sockets[i];
        }
    }

    return NULL;
}

// ------------------------------------------------------------------------------
// Test connect helper
// ------------------------------------------------------------------------------

socket* tcpConnect(uint8_t remoteIp[4], uint16_t remotePort, uint16_t localPort)
{
    socket *s = newSocket();
    uint8_t i;

    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(socket));

    for (i = 0; i < 4; i++)
        s->remoteIpAddress[i] = remoteIp[i];

    s->remotePort = remotePort;
    s->localPort = localPort;
    s->sequenceNumber = random32();
    s->acknowledgementNumber = 0;

    // Important: mark socket as active for outbound connect
    s->state = TCP_SYN_SENT;

    i = getSocketIndex(s);
    clearTcpPendingState(i);
    tcpArpPending[i] = true;

    putsUart0("tcpConnect: socket created\r\n");

    return s;
}

bool tcpIsConnected(socket *s)
{
    if (s == NULL) return false;
    return (s->state == TCP_ESTABLISHED);
}

bool tcpSend(socket *s, uint8_t data[], uint16_t dataSize)
{
    uint8_t i;

    if (s == NULL || data == NULL) return false;
    if (s->state != TCP_ESTABLISHED) return false;
    if (dataSize > TCP_TX_BUFFER_SIZE) return false;

    i = getSocketIndex(s);
    memcpy(tcpPendingTxData[i], data, dataSize);
    tcpPendingTxSize[i] = dataSize;
    tcpTxPending[i] = true;
    return true;
}

void tcpClose(socket *s)
{
    uint8_t i;

    if (s == NULL) return;
    if (s->state == TCP_ESTABLISHED)
    {
        i = getSocketIndex(s);
        tcpFinPending[i] = true;
    }
}

// ------------------------------------------------------------------------------
// State access
// ------------------------------------------------------------------------------

void setTcpState(uint8_t instance, uint8_t state)
{
    tcpState[instance] = state;
}

uint8_t getTcpState(uint8_t instance)
{
    return tcpState[instance];
}

// ------------------------------------------------------------------------------
// Packet classifiers
// ------------------------------------------------------------------------------

bool isTcp(etherHeader* ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t tcpLength;
    uint16_t rxChecksum;
    uint16_t calc;

    if (!isIp(ether)) return false;

    ip = (ipHeader*)ether->data;

    if (ip->protocol != PROTOCOL_TCP) return false;

    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    tcpLength = ntohs(ip->length) - ipHeaderLength;

    rxChecksum = tcp->checksum;
    calc = calcTcpChecksum(ip, tcp, tcpLength);
    tcp->checksum = rxChecksum;

    return (calc == rxChecksum);
}

bool isTcpSyn(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t flags;

    if (!isTcp(ether)) return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    flags = getTcpFlags(tcp);

    return ((flags & SYN) != 0);
}

bool isTcpAck(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t flags;

    if (!isTcp(ether)) return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    flags = getTcpFlags(tcp);

    return ((flags & ACK) != 0);
}

// ------------------------------------------------------------------------------
// Port list
// ------------------------------------------------------------------------------

void setTcpPortList(uint16_t ports[], uint8_t count)
{
    uint8_t i;

    if (count > MAX_TCP_PORTS)
        count = MAX_TCP_PORTS;

    tcpPortCount = count;

    for (i = 0; i < count; i++)
    {
        tcpPorts[i] = ports[i];
        tcpState[i] = TCP_LISTEN;
    }

    for (i = 0; i < count; i++)
    {
        socket *s = newSocket();
        if (s != NULL)
        {
            memset(s, 0, sizeof(socket));
            s->localPort = ports[i];
            s->state = TCP_LISTEN;
        }
    }
}

bool isTcpPortOpen(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t dstPort;
    uint8_t i;

    if (!isTcp(ether)) return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    dstPort = ntohs(tcp->destPort);

    for (i = 0; i < tcpPortCount; i++)
    {
        if (tcpPorts[i] == dstPort)
            return true;
    }

    return false;
}

// ------------------------------------------------------------------------------
// TCP transmit
// ------------------------------------------------------------------------------

void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags)
{
    sendTcpMessage(ether, s, flags, NULL, 0);
}

void sendTcpMessage(etherHeader *ether, socket* s, uint16_t flags, uint8_t data[], uint16_t dataSize)
{
    uint8_t i;
    uint8_t localIp[4];
    uint8_t localMac[6];

    ipHeader *ip = (ipHeader*)ether->data;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + sizeof(ipHeader));

    getIpAddress(localIp);
    getEtherMacAddress(localMac);

    for (i = 0; i < 6; i++)
    {
        ether->destAddress[i] = s->remoteHwAddress[i];
        ether->sourceAddress[i] = localMac[i];
    }
    ether->frameType = htons(TYPE_IP);

    ip->rev = 4;
    ip->size = 5;
    ip->typeOfService = 0;
    ip->id = htons(tcpIpId++);
    ip->flagsAndOffset = 0;
    ip->ttl = 64;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;

    for (i = 0; i < 4; i++)
    {
        ip->sourceIp[i] = localIp[i];
        ip->destIp[i] = s->remoteIpAddress[i];
    }

    tcp->sourcePort = htons(s->localPort);
    tcp->destPort = htons(s->remotePort);
    tcp->seq = htonl(s->sequenceNumber);
    tcp->ack = htonl(s->acknowledgementNumber);
    tcp->offsetFields = htons((5 << OFS_SHIFT) | flags);
    tcp->windowSize = htons(1460);
    tcp->urgentPointer = 0;
    tcp->checksum = 0;

    if (dataSize > 0 && data != NULL)
    {
        memcpy((uint8_t*)tcp + sizeof(tcpHeader), data, dataSize);
    }

    ip->length = htons(sizeof(ipHeader) + sizeof(tcpHeader) + dataSize);
    calcIpChecksum(ip);
    tcp->checksum = calcTcpChecksum(ip, tcp, sizeof(tcpHeader) + dataSize);

    putEtherPacket(ether, sizeof(etherHeader) + sizeof(ipHeader) + sizeof(tcpHeader) + dataSize);
}

void sendTcpPendingMessages(etherHeader *ether)
{
    uint8_t i;
    uint8_t zeroIp[4] = {0, 0, 0, 0};

    for (i = 0; i < MAX_TCP_SOCKETS; i++)
    {
        socket *s = &sockets[i];

        if (tcpArpPending[i])
        {
            sendArpRequest(ether, zeroIp, s->remoteIpAddress);
            tcpArpPending[i] = false;
            putsUart0("TCP ARP sent\r\n");
        }
        else if (tcpSynPending[i])
        {
            sendTcpMessage(ether, s, SYN, NULL, 0);
            s->sequenceNumber++;
            tcpSynPending[i] = false;
            putsUart0("TCP SYN sent\r\n");
        }
        else if (tcpTxPending[i] && s->state == TCP_ESTABLISHED)
        {
            sendTcpMessage(ether, s, PSH | ACK, tcpPendingTxData[i], tcpPendingTxSize[i]);
            s->sequenceNumber += tcpPendingTxSize[i];
            tcpPendingTxSize[i] = 0;
            tcpTxPending[i] = false;
        }
        else if (tcpFinPending[i] && s->state == TCP_ESTABLISHED)
        {
            sendTcpMessage(ether, s, FIN | ACK, NULL, 0);
            s->sequenceNumber++;
            s->state = TCP_FIN_WAIT_1;
            tcpFinPending[i] = false;
        }
    }
}

// ------------------------------------------------------------------------------
// ARP assist for TCP connect
// ------------------------------------------------------------------------------
void processTcpArpResponse(etherHeader *ether)
{
    arpPacket *arp = (arpPacket*)ether->data;
    uint8_t i;

    if (!isArpResponse(ether))
        return;

    for (i = 0; i < MAX_TCP_SOCKETS; i++)
    {
        if ((sockets[i].state == TCP_SYN_SENT) &&
            sockets[i].remoteIpAddress[0] == arp->sourceIp[0] &&
            sockets[i].remoteIpAddress[1] == arp->sourceIp[1] &&
            sockets[i].remoteIpAddress[2] == arp->sourceIp[2] &&
            sockets[i].remoteIpAddress[3] == arp->sourceIp[3])
        {
            memcpy(sockets[i].remoteHwAddress, arp->sourceAddress, 6);
            tcpSynPending[i] = true;
            putsUart0("TCP ARP reply received\r\n");
            return;
        }
    }
}

// ------------------------------------------------------------------------------
// TCP receive/state machine
// ------------------------------------------------------------------------------

void processTcpResponse(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    socket *s;
    uint8_t ipHeaderLength;
    uint16_t flags;
    uint16_t payloadLength;
    uint32_t remoteSeq;

    if (!isTcp(ether))
        return;

    putsUart0("TCP RX\r\n");

    s = findSocketByTuple(ether);
    if (s == NULL)
    {
        putsUart0("NO SOCKET MATCH\r\n");
        return;
    }

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    flags = getTcpFlags(tcp);
    payloadLength = getTcpPayloadLength(ether);
    remoteSeq = ntohl(tcp->seq);

    if (s->state == TCP_SYN_SENT)
    {
        if ((flags & SYN) && (flags & ACK))
        {
            s->acknowledgementNumber = remoteSeq + 1;
            sendTcpMessage(ether, s, ACK, NULL, 0);
            s->state = TCP_ESTABLISHED;
            putsUart0("TCP ESTABLISHED\r\n");
        }
        return;
    }

    if (s->state == TCP_ESTABLISHED)
    {
        if (payloadLength > 0)
        {
            s->acknowledgementNumber = remoteSeq + tcpControlLength(tcp, payloadLength);
            sendTcpMessage(ether, s, ACK, NULL, 0);
        }

        if (flags & FIN)
        {
            s->acknowledgementNumber = remoteSeq + 1;
            sendTcpMessage(ether, s, ACK, NULL, 0);
            s->state = TCP_CLOSE_WAIT;
            putsUart0("TCP CLOSE_WAIT\r\n");
        }
        return;
    }

    if (s->state == TCP_FIN_WAIT_1)
    {
        if ((flags & ACK) && !(flags & FIN))
        {
            s->state = TCP_FIN_WAIT_2;
            putsUart0("TCP FIN_WAIT_2\r\n");
            return;
        }

        if (flags & FIN)
        {
            s->acknowledgementNumber = remoteSeq + 1;
            sendTcpMessage(ether, s, ACK, NULL, 0);
            s->state = TCP_TIME_WAIT;
            putsUart0("TCP TIME_WAIT\r\n");
            return;
        }

        return;
    }

    if (s->state == TCP_FIN_WAIT_2)
    {
        if (flags & FIN)
        {
            s->acknowledgementNumber = remoteSeq + 1;
            sendTcpMessage(ether, s, ACK, NULL, 0);
            s->state = TCP_TIME_WAIT;
            putsUart0("TCP TIME_WAIT\r\n");
        }
        return;
    }

    if (s->state == TCP_CLOSE_WAIT)
    {
        return;
    }

    if (s->state == TCP_TIME_WAIT)
    {
        s->state = TCP_CLOSED;
        putsUart0("TCP CLOSED\r\n");
        return;
    }
}
