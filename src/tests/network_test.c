/**
 * @file network_test.c
 * @brief Tests the funtions declared in net.h.
 * @author Adam Bruce
 * @date 12 Feb 2021
 */

#include "../net.h"

#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/**
 * Tests if init_net is able to successfully initialise, and return a value to 0
 * to indicate success.
 */
void init_net_valid(void **state)
{
  assert_int_equal(init_net(), 0);
  cleanup_net();
}

/**
 * Tests if cleanup_net is able tp successfully cleanup the network API,
 * including closing down the relevant sockets.
 */
void cleanup_net_valid(void **state)
{
  init_net();
  assert_int_equal(cleanup_net(), 0);
}

/**
 * Tests if a message can be sent to another host using its IP address.
 */
void send_recv_valid(void **state)
{
  char send_buffer[12], recv_buffer[12];
  memset(send_buffer, '\0', 12);
  memset(recv_buffer, '\0', 12);
  strcpy(send_buffer, "Hello World");

  init_net();
  send_to_host("127.0.0.1", send_buffer, 12);
  poll_message(recv_buffer, 12);
  cleanup_net();
  
  assert_string_equal(recv_buffer, send_buffer);
}

int main(void)
{
  const struct CMUnitTest tests[] =
    {
      cmocka_unit_test(init_net_valid),
      cmocka_unit_test(cleanup_net_valid),
      cmocka_unit_test(send_recv_valid),
    };

  cmocka_run_group_tests(tests, NULL, NULL);
  return 0;
}
