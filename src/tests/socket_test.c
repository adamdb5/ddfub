/**
 * @file socket_test.c
 * @brief Tests the functions declared in socket.h.
 * @author Adam Bruce
 * @date 12 Feb 2021
 */

#include "../socket.h"

#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/**
 * Tests if init_sockets is able to succesfully initialise, and return a value
 * of 0 to indicate success.
 */
void init_sockets_valid(void **state)
{
  assert_int_equal(init_sockets(), 0);
  cleanup_sockets();
}

/**
 * Tests if cleanup_sockets is able to successfully cleanup the relevant socket
 * API, and return a value of 0 to indicate success.
 */
void cleanup_sockets_valid(void **state)
{
  init_sockets();
  assert_int_equal(cleanup_sockets(), 0);
}

/**
 * Tests if a socket can be successfully created.
 */
void create_socket_valid(void **state)
{
  init_sockets();
  assert_int_not_equal(create_socket(), 0);
  cleanup_sockets();
}

/**
 * Tests if a socket can be bound to the sending port.
 */
void bind_send_socket_valid(void **state)
{
  socket_t sock;
  init_sockets();
  sock = create_socket();
  assert_int_equal(bind_socket(sock, 8071), 0);
  close_socket(sock);
  cleanup_sockets();
}

/**
 * Tests if a socket can be bound to the receiving port.
 */
void bind_recv_socket_valid(void **state)
{
  socket_t sock;
  init_sockets();
  sock = create_socket();
  assert_int_equal(bind_socket(sock, 8070), 0);
  close_socket(sock);
  cleanup_sockets();
}

/**
 * Tests to ensure a non-zero value is returned when attempting to bind to a
 * non-existant socket.
 */
void bind_socket_null_socket(void **state)
{
  socket_t sock;
  init_sockets();
  sock = create_socket();
  assert_int_not_equal(bind_socket(0, 8070), 0);
  close_socket(sock);
  cleanup_sockets();
}

/**
 * Tests to ensure a non-zero value is returned when attempting to bind to a
 * port that is already in use.
 */
void bind_socket_port_reuse(void **state)
{
  socket_t sock1, sock2;
  init_sockets();
  sock1 = create_socket();
  sock2 = create_socket();
  bind_socket(sock1, 8070);
  assert_int_not_equal(bind_socket(sock2, 8070), 0);
  close_socket(sock1);
  close_socket(sock2);
  cleanup_sockets();
}

/**
 * Tests if a sending and receiving socket can be opened, and succesfully
 * communicate between the two sockets.
 */
void send_recv_valid(void **state)
{
  socket_t sock_send, sock_recv;
  struct sockaddr_in addr_in;
  char send_buffer[13], recv_buffer[13];

  memset(send_buffer, '\0', 13);
  memset(recv_buffer, '\0', 13);
  strcpy(send_buffer, "Hello World\n");
  
  addr_in.sin_family = AF_INET;
  addr_in.sin_addr.s_addr = INADDR_ANY;
  addr_in.sin_port = htons(8070);
  
  init_sockets();
  sock_send = create_socket();
  sock_recv = create_socket();
  bind_socket(sock_send, 8071);
  bind_socket(sock_recv, 8070);

  send_to_socket(sock_send, (void*)send_buffer, 13, 0, addr_in);
  recv_from_socket(sock_recv, recv_buffer, 13, 0);
  assert_string_equal(send_buffer, recv_buffer);

  close_socket(sock_send);
  close_socket(sock_recv);
  cleanup_sockets();
}

int main(void)
{
  const struct CMUnitTest tests[] =
    {
      cmocka_unit_test(init_sockets_valid),
      cmocka_unit_test(cleanup_sockets_valid),
      cmocka_unit_test(create_socket_valid),
      cmocka_unit_test(bind_send_socket_valid),
      cmocka_unit_test(bind_recv_socket_valid),
      cmocka_unit_test(bind_socket_null_socket),
      cmocka_unit_test(bind_socket_port_reuse),
      cmocka_unit_test(send_recv_valid),
    };

  cmocka_run_group_tests(tests, NULL, NULL);
  return 0;
}
