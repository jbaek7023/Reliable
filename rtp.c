#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "rtp.h"

/* GIVEN Function:
 * Handles creating the client's socket and determining the correct
 * information to communicate to the remote server
 */
CONN_INFO* setup_socket(char* ip, char* port){
	struct addrinfo *connections, *conn = NULL;
	struct addrinfo info;
	memset(&info, 0, sizeof(struct addrinfo));
	int sock = 0;

	info.ai_family = AF_INET;
	info.ai_socktype = SOCK_DGRAM;
	info.ai_protocol = IPPROTO_UDP;
	getaddrinfo(ip, port, &info, &connections);

	/*for loop to determine corr addr info*/
	for(conn = connections; conn != NULL; conn = conn->ai_next){
		sock = socket(conn->ai_family, conn->ai_socktype, conn->ai_protocol);
		if(sock <0){
			if(DEBUG)
				perror("Failed to create socket\n");
			continue;
		}
		if(DEBUG)
			printf("Created a socket to use.\n");
		break;
	}
	if(conn == NULL){
		perror("Failed to find and bind a socket\n");
		return NULL;
	}
	CONN_INFO* conn_info = malloc(sizeof(CONN_INFO));
	conn_info->socket = sock;
	conn_info->remote_addr = conn->ai_addr;
	conn_info->addrlen = conn->ai_addrlen;
	return conn_info;
}

void shutdown_socket(CONN_INFO *connection){
	if(connection)
		close(connection->socket);
}

/* 
 * ===========================================================================
 *
 *			STUDENT CODE STARTS HERE. PLEASE COMPLETE ALL FIXMES
 *
 * ===========================================================================
 */


/*
 *  Returns a number computed based on the data in the buffer.
 */
static int checksum(char *buffer, int length){
	int i, sum;
	sum = 0;
	for(i=0;i<length;i++) {
		sum += buffer[i];
	}
	return sum;
}

/*
 *  Converts the given buffer into an array of PACKETs and returns
 *  the array.  The value of (*count) should be updated so that it 
 *  contains the length of the array created.
 */
static PACKET* packetize(char *buffer, int length, int *count){
	int i,p ;
	PACKET* packet;
	int size = (length + MAX_PAYLOAD_LENGTH - 1) / MAX_PAYLOAD_LENGTH;
	*count = size;
	PACKET* packets = calloc(size,sizeof(PACKET));
	
	for(i=0; i<length; i++) {
		packet = packets + (i / MAX_PAYLOAD_LENGTH);
		p = (i % MAX_PAYLOAD_LENGTH);
		packet->payload[p] = buffer[i];

		if(i == (length - 1)) {
			packet->type = LAST_DATA;
			packet->payload_length = p + 1;
			packet->checksum = checksum(packet->payload,packet->payload_length);
		} else if(p == MAX_PAYLOAD_LENGTH - 1) {
			packet->type = DATA;
			packet->payload_length = MAX_PAYLOAD_LENGTH;
			packet->checksum = checksum(packet->payload,packet->payload_length);
		}
	}
	return packets;
}

/*
 * Send a message via RTP using the connection information
 * given on UDP socket functions sendto() and recvfrom()
 */
int rtp_send_message(CONN_INFO *connection, MESSAGE*msg){
	int array_size=0;
	PACKET* packets = packetize(msg->buffer, msg->length, &array_size);
	int i;
	PACKET* buffer;
	buffer = malloc(sizeof(PACKET));
	for (i = 0; i < array_size; i++){
		sendto(connection->socket, &packets[i], sizeof(PACKET), 0, connection->remote_addr, connection->addrlen);
		recvfrom(connection->socket, buffer, sizeof(PACKET), 0, NULL, NULL);
		PACKET *packet = buffer;
		if(packet->type==ACK){
		/*send the next one*/
		} else if (packet->type == NACK){
		/*Get back to ma loop!*/
			i--;
		}
	}
	return 1;
}

/*
 * Receive a message via RTP using the connection information
 * given on UDP socket functions sendto() and recvfrom()
 */
MESSAGE* rtp_receive_message(CONN_INFO *connection){
	MESSAGE* message;
	message = malloc(sizeof(MESSAGE));
	PACKET* packet;
	packet = malloc(sizeof(PACKET));

	/*packet->type == data ->>>> payload add to current message buffer.*/
	/*add packet's payload to the buffer only if checksum of the data matches the checksum in the packe header*/
	/*If checksum match, you should send an response packet sendto with empty payload*/
	/*If checksum doesn't match, you should send a NACK packet*/
	do {
		int data = recvfrom(connection->socket, packet, sizeof(PACKET), 0, NULL, NULL);
		if (data == sizeof(PACKET)){
			PACKET* packet2 = (PACKET*) packet;
			PACKET* response = malloc(sizeof(PACKET));
			int csv;	//checksum value
			csv = checksum(packet2->payload, packet2->payload_length);
			if (packet2->checksum == csv){
				char* new_packet = malloc((sizeof(char) * packet2->payload_length) + sizeof(char) * message->length);
				memcpy(new_packet, message->buffer, message->length);
				memcpy(new_packet + message->length, packet2->payload, packet2->payload_length);
				message->length = message->length + packet2->payload_length;
				message->buffer = new_packet;
				response->type = ACK;
				sendto(connection->socket, response, sizeof(PACKET), 0, connection->remote_addr, (socklen_t)connection->addrlen);
				if (packet2->type == LAST_DATA){				
					return message;
				}
			} else {
				response->type = NACK;
				sendto(connection->socket, response, sizeof(PACKET), 0, connection->remote_addr, (socklen_t)connection->addrlen);
			}
		}
	}while(1);
	return message;
}
