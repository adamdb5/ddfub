/**
 * @file main.c
 * @brief Entry point for the application.
 * @author Adam Bruce
 * @date 15 Dec 2020
 */

#include "socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define PORT_IN  8070
#define PORT_OUT 8071

int main(void)
{
	socket_t sock_in, sock_out;
	struct sockaddr_in addr_in;
	char buffer[6];
	char buffer_in[1000];
	
	addr_in.sin_family = AF_INET;
	addr_in.sin_addr.s_addr = INADDR_ANY;
	addr_in.sin_port = htons(PORT_IN);
	
	/* Initialise socket APIs */
	init_sockets();

	/* Create the receiving socket */
	if((sock_in = create_socket()) == INVALID_SOCKET)
	{
		perror("create sock_in");
		return EXIT_FAILURE;
	}
	
	/* Create the sending socket */
	if((sock_out = create_socket()) == INVALID_SOCKET)
	{
		perror("create sock_out");
		return EXIT_FAILURE;
	}
	
	/* Bind the receiving socket */
	if(bind_socket(sock_in, PORT_IN) != 0)
	{
		perror("bind sock_in");
		return EXIT_FAILURE;
	}
	
	/* Bind the sending socket */
	if(bind_socket(sock_out, PORT_OUT) != 0)
	{
		perror("bind sock_out");
		return EXIT_FAILURE;
	}
	
	/* Success */
	printf("Socket creation and bind successful!\n");
	
	/* Send a message to ourself */
	strcpy(buffer, "hello");
	send_to_socket(sock_out, (void*)buffer, strlen(buffer), 0, addr_in);
		   
	/* Receive the message */
	recv_from_socket(sock_in, buffer_in, 1000, 0);
	
	/* Print our received message */
	printf("Received: %s\n", buffer_in);
	
	/* Close sockets */
	close_socket(sock_in);
	close_socket(sock_out);
	
	/* Cleanup socket APIs */
	cleanup_sockets();
	
	return 0;
}
