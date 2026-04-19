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

#ifndef TCP_H_
#define TCP_H_

#include <stdbool.h>
#include <stdint.h>
#include "socket.h"

#define SYN 0x002
#define ACK 0x010
#define PSH 0x008
#define FIN 0x001
#define RST 0x004

#define OFS_SHIFT 12

#define TCP_CLOSED       0
#define TCP_LISTEN       1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECEIVED 3
#define TCP_ESTABLISHED  4
#define TCP_FIN_WAIT_1   5
#define TCP_FIN_WAIT_2   6
#define TCP_CLOSE_WAIT   7
#define TCP_LAST_ACK     8
#define TCP_TIME_WAIT    9

#define MAX_TCP_PORTS 4
#define TCP_TX_BUFFER_SIZE 512

typedef struct _tcpHeader
{
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t seq;
    uint32_t ack;
    uint16_t offsetFields;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
    uint8_t data[0];
} tcpHeader;

void setTcpState(uint8_t instance, uint8_t state);
uint8_t getTcpState(uint8_t instance);

bool isTcp(etherHeader* ether);
bool isTcpSyn(etherHeader *ether);
bool isTcpAck(etherHeader *ether);

void setTcpPortList(uint16_t ports[], uint8_t count);
bool isTcpPortOpen(etherHeader *ether);

void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags);
void sendTcpMessage(etherHeader *ether, socket* s, uint16_t flags, uint8_t data[], uint16_t dataSize);
void sendTcpPendingMessages(etherHeader *ether);
void processTcpArpResponse(etherHeader *ether);
void processTcpResponse(etherHeader *ether);

bool tcpIsConnected(socket *s);
bool tcpSend(socket *s, uint8_t data[], uint16_t dataSize);
void tcpClose(socket *s);

socket* tcpConnect(uint8_t remoteIp[4], uint16_t remotePort, uint16_t localPort);

#endif
