// TCP Library
// Jason Losh
//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------
// Target Platform: -
// Target uC: -
// System Clock: -
// Hardware configuration:
// -
//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "arp.h"
#include "tcp.h"
#include "timer.h"

// ------------------------------------------------------------------------------
// Globals
// ------------------------------------------------------------------------------

// Socket table comes from socket.c
extern socket sockets[MAX_TCP_SOCKETS];

// These are kept only because tcp.h already expects them.
// In this client-only version they are mostly unused.
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

// ------------------------------------------------------------------------------
// Local helpers
// ------------------------------------------------------------------------------

/*
 * Returns the socket index from a socket pointer.
 * This works because sockets[] is a contiguous array in memory.
 */
static uint8_t getSocketIndex(socket *s)
{
    return (uint8_t)(s - sockets);
}

/*
 * Clears all client-side pending flags and pending TX buffer info
 * for one socket index.
 */
static void clearTcpPendingState(uint8_t i)
{
    tcpArpPending[i] = false;
    tcpSynPending[i] = false;
    tcpTxPending[i] = false;
    tcpFinPending[i] = false;
    tcpPendingTxSize[i] = 0;
}

/*
 * Returns TCP header length in bytes.
 * TCP stores header length in 32-bit words, so multiply by 4.
 */
static uint8_t getTcpHeaderLengthBytes(tcpHeader *tcp)
{
    return (uint8_t)((ntohs(tcp->offsetFields) >> OFS_SHIFT) * 4);
}

/*
 * Returns the 9-bit TCP flags field (SYN, ACK, FIN, etc).
 */
static uint16_t getTcpFlags(tcpHeader *tcp)
{
    return (uint16_t)(ntohs(tcp->offsetFields) & 0x01FF);
}

/*
 * Returns total TCP segment length = TCP header + payload.
 * IP total length includes IP header + TCP segment,
 * so subtract the IP header length.
 */
static uint16_t getTcpSegmentLength(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint16_t ipLength = ntohs(ip->length);
    uint16_t ipHeaderLength = ip->size * 4;
    return ipLength - ipHeaderLength;
}

/*
 * Returns only the TCP payload length.
 * payload = total TCP segment length - TCP header length
 */
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

/*
 * Returns pointer to TCP payload data.
 * This is the first byte after the TCP header.
 */
static uint8_t *getTcpPayload(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint8_t tcpHeaderLength = getTcpHeaderLengthBytes(tcp);

    return ((uint8_t*)tcp + tcpHeaderLength);
}

/*
 * Returns how much sequence space a received segment consumes.
 * SYN counts as 1, FIN counts as 1, payload counts as payloadLength.
 */
static uint32_t tcpControlLength(tcpHeader *tcp, uint16_t payloadLength)
{
    uint16_t flags = getTcpFlags(tcp);
    uint32_t amount = payloadLength;

    if (flags & SYN) amount++;
    if (flags & FIN) amount++;

    return amount;
}

/*
 * Adds the TCP pseudo-header fields into the checksum sum.
 * TCP checksum includes:
 * - source IP
 * - destination IP
 * - protocol
 * - TCP length
 */
static void sumTcpPseudoHeader(ipHeader *ip, uint16_t tcpLength, uint32_t *sum)
{
    sumIpWords(ip->sourceIp, 4, sum);
    sumIpWords(ip->destIp, 4, sum);

    *sum += 0;
    *sum += PROTOCOL_TCP << 8;

    *sum += (tcpLength & 0x00FF) << 8;
    *sum += (tcpLength & 0xFF00) >> 8;
}

/*
 * Calculates TCP checksum over:
 * - pseudo-header
 * - TCP header
 * - TCP payload
 */
static uint16_t calcTcpChecksum(ipHeader *ip, tcpHeader *tcp, uint16_t tcpLength)
{
    uint32_t sum = 0;

    tcp->checksum = 0;
    sumTcpPseudoHeader(ip, tcpLength, &sum);
    sumIpWords(tcp, tcpLength, &sum);

    return getIpChecksum(sum);
}

/*
 * Returns true if two IP addresses match.
 */
static bool isIpAddressMatch(const uint8_t a[4], const uint8_t b[4])
{
    return (memcmp(a, b, 4) == 0);
}

/*
 * Finds a socket that matches the incoming packet's connection tuple:
 * local port, remote port, remote IP.
 *
 * Since this is client-side only, we only care about packets that belong
 * to a connection we previously started.
 */
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
        if (sockets[i].state != TCP_CLOSED &&
            sockets[i].localPort == dstPort &&
            sockets[i].remotePort == srcPort &&
            isIpAddressMatch(sockets[i].remoteIpAddress, ip->sourceIp))
        {
            return &sockets[i];
        }
    }

    return NULL;
}

// ------------------------------------------------------------------------------
// Public client helpers
// ------------------------------------------------------------------------------

/*
 * Creates a client TCP socket and starts the ARP -> SYN connect sequence.
 *
 * This function is not declared in tcp.h on purpose since you asked to avoid
 * changing the header. Later in mqtt.c you can declare it with:
 *
 * extern socket* tcpConnect(uint8_t remoteIp[4], uint16_t remotePort, uint16_t localPort);
 */
socket* tcpConnect(uint8_t remoteIp[4], uint16_t remotePort, uint16_t localPort)
{
    socket *s = newSocket();
    uint8_t i;

    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(socket));

    memcpy(s->remoteIpAddress, remoteIp, 4);
    s->remotePort = remotePort;
    s->localPort = localPort;
    s->sequenceNumber = random32();       // initial local sequence number
    s->acknowledgementNumber = 0;
    s->state = TCP_CLOSED;

    i = getSocketIndex(s);
    clearTcpPendingState(i);

    // First we need remote MAC address, so start with ARP
    tcpArpPending[i] = true;

    return s;
}

/*
 * Returns true if socket is connected and fully established.
 */
bool tcpIsConnected(socket *s)
{
    if (s == NULL)
        return false;

    return (s->state == TCP_ESTABLISHED);
}

/*
 * Queues application data for transmit.
 * Data will be sent later by sendTcpPendingMessages().
 */
bool tcpSend(socket *s, uint8_t data[], uint16_t dataSize)
{
    uint8_t i;

    if (s == NULL || data == NULL)
        return false;

    if (s->state != TCP_ESTABLISHED)
        return false;

    if (dataSize > TCP_TX_BUFFER_SIZE)
        return false;

    i = getSocketIndex(s);

    memcpy(tcpPendingTxData[i], data, dataSize);
    tcpPendingTxSize[i] = dataSize;
    tcpTxPending[i] = true;

    return true;
}

/*
 * Requests graceful TCP close.
 * Actual FIN will be sent by sendTcpPendingMessages().
 */
void tcpClose(socket *s)
{
    uint8_t i;

    if (s == NULL)
        return;

    if (s->state == TCP_ESTABLISHED)
    {
        i = getSocketIndex(s);
        tcpFinPending[i] = true;
    }
}

// ------------------------------------------------------------------------------
// State access
// ------------------------------------------------------------------------------

/*
 * Stores TCP state for a given listening-port instance.
 *
 * This array is separate from per-socket state.
 * It can be used to remember the state associated with each
 * registered TCP port entry.
 */
void setTcpState(uint8_t instance, uint8_t state)
{
    tcpState[instance] = state;
}

/*
 * Returns stored TCP state for a given listening-port instance.
 */
uint8_t getTcpState(uint8_t instance)
{
    return tcpState[instance];
}
// ------------------------------------------------------------------------------
// Packet classifiers
// ------------------------------------------------------------------------------

/*
 * Determines whether an incoming Ethernet frame contains a valid TCP packet.
 *
 * Checks:
 * 1. Ethernet frame must contain IP
 * 2. IP protocol field must say TCP
 * 3. TCP checksum must be correct
 *
 * Returns true only if all checks pass.
 */
bool isTcp(etherHeader* ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t tcpLength;
    uint16_t rxChecksum;
    uint16_t calc;

    // Must be an IP packet first
    if (!isIp(ether))
        return false;

    ip = (ipHeader*)ether->data;

    // IP protocol must be TCP
    if (ip->protocol != PROTOCOL_TCP)
        return false;

    // Find TCP header
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // Total TCP bytes = IP total length - IP header length
    tcpLength = ntohs(ip->length) - ipHeaderLength;

    // Save received checksum
    rxChecksum = tcp->checksum;

    // Recalculate checksum
    calc = calcTcpChecksum(ip, tcp, tcpLength);

    // Restore original checksum field
    tcp->checksum = rxChecksum;

    return (calc == rxChecksum);
}

/*
 * Returns true if the packet is valid TCP and has SYN set.
 *
 * SYN is used to begin a TCP connection.
 */
bool isTcpSyn(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t flags;

    if (!isTcp(ether))
        return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    flags = getTcpFlags(tcp);

    return ((flags & SYN) != 0);
}

/*
 * Returns true if the packet is valid TCP and has ACK set.
 *
 * ACK is used throughout TCP to acknowledge received sequence numbers.
 */
bool isTcpAck(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t flags;

    if (!isTcp(ether))
        return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    flags = getTcpFlags(tcp);

    return ((flags & ACK) != 0);
}

// ------------------------------------------------------------------------------
// Port list
// ------------------------------------------------------------------------------

/*
 * Configures which TCP ports this device is listening on.
 *
 * For each port:
 * - store it in tcpPorts[]
 * - mark its state as TCP_LISTEN
 * - allocate a listening socket
 *
 * This supports passive-open behavior:
 * the board sits in LISTEN until a remote device sends SYN.
 */
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

    // Create listening sockets for the configured ports
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

/*
 * Returns true if the destination port of the incoming packet
 * matches one of the open TCP ports for this device.
 *
 * Used by main loop to decide whether to process packet or reject it.
 */
bool isTcpPortOpen(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t dstPort;
    uint8_t i;

    if (!isTcp(ether))
        return false;

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

/*
 * Sends a TCP response with no payload.
 *
 * This is a convenience wrapper around sendTcpMessage().
 * Used for control packets such as:
 * - ACK
 * - SYN+ACK
 * - FIN+ACK
 * - ACK+RST
 */
void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags)
{
    sendTcpMessage(ether, s, flags, NULL, 0);
}

/*
 * Builds and sends an outgoing TCP packet.
 *
 * This function creates:
 * - Ethernet header
 * - IP header
 * - TCP header
 * - optional TCP payload
 *
 * It then calculates TCP checksum and transmits the frame.
 *
 * The function also updates local sequence number after sending:
 * - +1 if SYN sent
 * - +1 if FIN sent
 * - +dataSize if payload sent
 */
void sendTcpMessage(etherHeader *ether, socket *s, uint16_t flags, uint8_t data[], uint16_t dataSize)
{
    ipHeader *rxIp;
    tcpHeader *rxTcp;
    ipHeader *txIp;
    tcpHeader *txTcp;
    uint8_t ipHeaderLength;
    uint8_t localMac[6];
    uint8_t localIp[4];
    uint16_t tcpHeaderLength = 20;
    uint16_t tcpLength = tcpHeaderLength + dataSize;
    uint16_t ipLength = 20 + tcpLength;
    uint16_t frameLength = 14 + ipLength;
    uint8_t i;

    // Get this device's MAC and IP
    getEtherMacAddress(localMac);
    getIpAddress(localIp);

    if (ether == NULL || s == NULL)
        return;

    // Reference incoming packet info if needed
    rxIp = (ipHeader*)ether->data;
    ipHeaderLength = rxIp->size * 4;
    rxTcp = (tcpHeader*)((uint8_t*)rxIp + ipHeaderLength);

    // Build Ethernet header
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s->remoteHwAddress[i];
        ether->sourceAddress[i] = localMac[i];
    }
    ether->frameType = htons(TYPE_IP);

    // Build IP header
    txIp = (ipHeader*)ether->data;
    txIp->rev = 4;
    txIp->size = 5;                  // no IP options, so 20-byte IP header
    txIp->typeOfService = 0;
    txIp->length = htons(ipLength);
    txIp->id = 0;
    txIp->flagsAndOffset = 0;
    txIp->ttl = 64;
    txIp->protocol = PROTOCOL_TCP;
    txIp->headerChecksum = 0;

    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        txIp->sourceIp[i] = localIp[i];
        txIp->destIp[i] = s->remoteIpAddress[i];
    }

    // Calculate IP header checksum
    calcIpChecksum(txIp);

    // Build TCP header
    txTcp = (tcpHeader*)((uint8_t*)txIp + 20);
    txTcp->sourcePort = htons(s->localPort);
    txTcp->destPort = htons(s->remotePort);
    txTcp->sequenceNumber = htonl(s->sequenceNumber);
    txTcp->acknowledgementNumber = htonl(s->acknowledgementNumber);
    txTcp->offsetFields = htons((5 << OFS_SHIFT) | (flags & 0x01FF));
    txTcp->windowSize = htons(TCP_WINDOW_SIZE);
    txTcp->checksum = 0;
    txTcp->urgentPointer = 0;

    // Copy payload if present
    if (dataSize > 0 && data != NULL)
        memcpy(txTcp->data, data, dataSize);

    // Calculate TCP checksum
    txTcp->checksum = calcTcpChecksum(txIp, txTcp, tcpLength);

    // Send packet out on Ethernet
    putEtherPacket(ether, frameLength);

    // Advance local sequence number for anything we sent
    if ((flags & SYN) != 0)
        s->sequenceNumber++;

    if ((flags & FIN) != 0)
        s->sequenceNumber++;

    s->sequenceNumber += dataSize;
}

// ------------------------------------------------------------------------------
// Pending transmissions
// ------------------------------------------------------------------------------

/*
 * Drives client-side TCP actions from the main loop.
 *
 * Per socket:
 * 1. If ARP is pending, send ARP request for remote IP
 * 2. If SYN is pending, send SYN and enter SYN_SENT
 * 3. If data is pending and connection is ESTABLISHED, send PSH|ACK
 * 4. If close is pending, send FIN|ACK and enter FIN_WAIT_1
 */
void sendTcpPendingMessages(etherHeader *ether)
{
    uint8_t i;
    uint8_t localIp[4];

    getIpAddress(localIp);

    for (i = 0; i < MAX_TCP_SOCKETS; i++)
    {
        // 1) Need remote MAC first
        if (tcpArpPending[i] && sockets[i].state == TCP_CLOSED)
        {
            tcpArpPending[i] = false;
            sendArpRequest(ether, localIp, sockets[i].remoteIpAddress);
        }

        // 2) Ready to start TCP handshake
        else if (tcpSynPending[i] && sockets[i].state == TCP_CLOSED)
        {
            tcpSynPending[i] = false;
            sockets[i].state = TCP_SYN_SENT;
            sendTcpMessage(ether, &sockets[i], SYN, NULL, 0);
        }

        // 3) Send pending application data
        else if (tcpTxPending[i] && sockets[i].state == TCP_ESTABLISHED)
        {
            tcpTxPending[i] = false;
            sendTcpMessage(ether, &sockets[i], ACK | PSH,
                           tcpPendingTxData[i], tcpPendingTxSize[i]);
            tcpPendingTxSize[i] = 0;
        }

        // 4) Graceful close
        else if (tcpFinPending[i] && sockets[i].state == TCP_ESTABLISHED)
        {
            tcpFinPending[i] = false;
            sendTcpResponse(ether, &sockets[i], FIN | ACK);
            sockets[i].state = TCP_FIN_WAIT_1;
        }
    }
}


// ------------------------------------------------------------------------------
// ARP callback hook
// ------------------------------------------------------------------------------

/*
 * Called when an ARP response comes in.
 *
 * If the ARP response matches the remote IP of one of our sockets,
 * copy the remote MAC address into the socket and mark SYN pending.
 *
 * This allows the next pass through sendTcpPendingMessages() to send SYN.
 */
void processTcpArpResponse(etherHeader *ether)
{
    uint8_t i;
    arpPacket *arp;

    if (!isArpResponse(ether))
        return;

    arp = (arpPacket*)ether->data;

    for (i = 0; i < MAX_TCP_SOCKETS; i++)
    {
        if (sockets[i].state == TCP_CLOSED &&
            isIpAddressMatch(sockets[i].remoteIpAddress, arp->sourceIp))
        {
            memcpy(sockets[i].remoteHwAddress, arp->sourceAddress, 6);
            tcpSynPending[i] = true;
        }
    }
}

// ------------------------------------------------------------------------------
// Receive processing
// ------------------------------------------------------------------------------

/*
 * Main client-side TCP state machine.
 *
 * Only handles packets belonging to sockets that WE opened.
 *
 * States handled:
 * - TCP_SYN_SENT
 * - TCP_ESTABLISHED
 * - TCP_FIN_WAIT_1
 * - TCP_FIN_WAIT_2
 * - TCP_CLOSE_WAIT
 * - TCP_LAST_ACK
 * - TCP_TIME_WAIT
 */
void processTcpResponse(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    socket *s;
    uint8_t ipHeaderLength;
    uint16_t flags;
    uint16_t payloadLength;
    uint32_t seq;
    uint32_t ack;
    uint32_t segLen;

    if (!isTcp(ether))
        return;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    flags = getTcpFlags(tcp);
    payloadLength = getTcpPayloadLength(ether);
    seq = ntohl(tcp->sequenceNumber);
    ack = ntohl(tcp->acknowledgementNumber);
    segLen = tcpControlLength(tcp, payloadLength);

    // Only process packets that match a client socket we already created
    s = findSocketByTuple(ether);
    if (s == NULL)
        return;

    switch (s->state)
    {
        case TCP_CLOSED:
        {
            // We do nothing here.
            // Active open starts from sendTcpPendingMessages().
            break;
        }

        case TCP_SYN_SENT:
        {
            // Expecting SYN+ACK from the broker
            if ((flags & SYN) && (flags & ACK))
            {
                // ACK number from peer should acknowledge our SYN
                if (ack == s->sequenceNumber)
                {
                    // Expect the next byte after peer's SYN
                    s->acknowledgementNumber = seq + 1;

                    // Send final ACK of the 3-way handshake
                    sendTcpResponse(ether, s, ACK);

                    // Connection is now open
                    s->state = TCP_ESTABLISHED;
                }
            }
            else if (flags & RST)
            {
                uint8_t i = getSocketIndex(s);
                s->state = TCP_CLOSED;
                clearTcpPendingState(i);
                return;
            }
            break;
        }

        case TCP_ESTABLISHED:
        {
            // If data and/or FIN arrived, acknowledge everything consumed
            if (segLen > 0)
            {
                s->acknowledgementNumber = seq + segLen;
                sendTcpResponse(ether, s, ACK);
            }

            // If broker closes first, move into passive-close path
            if (flags & FIN)
            {
                // In this minimal client stack, send FIN|ACK immediately
                s->acknowledgementNumber = seq + 1;
                sendTcpResponse(ether, s, ACK);
                s->state = TCP_CLOSE_WAIT;
            }

            // Bare ACKs do not require action in this minimal implementation
            break;
        }

        case TCP_FIN_WAIT_1:
        {
            // Waiting for ACK of our FIN, and possibly peer FIN

            if (flags & ACK)
                s->state = TCP_FIN_WAIT_2;

            if (flags & FIN)
            {
                s->acknowledgementNumber = seq + 1;
                sendTcpResponse(ether, s, ACK);
                s->state = TCP_TIME_WAIT;
            }

            break;
        }

        case TCP_FIN_WAIT_2:
        {
            // Waiting for peer FIN
            if (flags & FIN)
            {
                s->acknowledgementNumber = seq + 1;
                sendTcpResponse(ether, s, ACK);
                s->state = TCP_TIME_WAIT;
            }
            break;
        }

        case TCP_CLOSE_WAIT:
        {
            // Not normally used in this client-only simplified path
            sendTcpResponse(ether, s, FIN | ACK);
            s->state = TCP_LAST_ACK;
            break;
        }

        case TCP_LAST_ACK:
        {
            // Waiting for peer to ACK our FIN
            if (flags & ACK)
            {
                uint8_t i = getSocketIndex(s);
                s->state = TCP_CLOSED;
                clearTcpPendingState(i);
            }
            break;
        }

        case TCP_TIME_WAIT:
        {
            // Minimal simplification: immediately close
            {
                uint8_t i = getSocketIndex(s);
                s->state = TCP_CLOSED;
                clearTcpPendingState(i);
            }
            break;
        }

        default:
            break;
    }
}
