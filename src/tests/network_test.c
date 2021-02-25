/**
 * @file network_test.c
 * @brief Tests the funtions declared in net.h.
 * @author Adam Bruce
 * @date 12 Feb 2021
 */

#include "../net.h"

#include <string.h>
#include <stdio.h>
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

void remove_me(void** state)
{
  init_net();
  AdvertisementMessage message;
  message.hops = 0;
  message.type = ADVERTISEMENT;
  message.advertisement_type = BROADCAST;
  strcpy(message.source_addr, "56.56.56.56");
  strcpy(message.target_addr, "127.0.0.1");
  send_advertisement_message(&message);

  char buffer[100];
  size_t length = 100;
  poll_message(buffer, length);
  cleanup_net();
}

void get_ip_address(void **state)
{
  /* Get IP address from command-line */
  FILE *fp;
  char addr_cl[INET_ADDRSTRLEN];
  char* newline_ptr;
  
  fp = popen("ifconfig wlan0 | grep \"inet\\s\" | cut -d' ' -f10", "r");
  while (fgets(addr_cl, sizeof(addr_cl), fp) != NULL);
  pclose(fp);
  if((newline_ptr = strchr(addr_cl, '\n')) != 0)
    {
      *newline_ptr = '\0';
    }
  if((newline_ptr = strchr(addr_cl, '\r')) != 0)
    {
      *newline_ptr = '\0';
    }

  /* Get IP address from function */
  char addr_func[INET_ADDRSTRLEN];
  get_local_address(addr_func);
  assert_string_equal(addr_cl, addr_func); 
}

void send_advertisement_broadcast(void)
{
  init_net();
  AdvertisementMessage message;
  message.hops = 0;
  message.type = ADVERTISEMENT;
  message.advertisement_type = BROADCAST;
  strcpy(message.source_addr, "56.56.56.56");
  strcpy(message.target_addr, "127.0.0.1");
  send_advertisement_message(&message);
  cleanup_net();
}

void send_advertisement_ack(void)
{
  init_net();
  AdvertisementMessage message;
  message.hops = 0;
  message.type = ADVERTISEMENT;
  message.advertisement_type = ACK;
  strcpy(message.source_addr, "56.56.56.56");
  strcpy(message.target_addr, "127.0.0.1");
  send_advertisement_message(&message);
  cleanup_net(); 
}

void send_advertisement_reject(void)
{
  init_net();
  AdvertisementMessage message;
  message.hops = 0;
  message.type = ADVERTISEMENT;
  message.advertisement_type = REJECT;
  strcpy(message.source_addr, "56.56.56.56");
  strcpy(message.target_addr, "127.0.0.1");
  send_advertisement_message(&message);
  cleanup_net(); 
}

void test_load_hosts_from_file(void)
{
  init_net();
  load_hosts_from_file("hosts.txt");
  cleanup_net();
}

void test_print_hosts(void)
{
  init_net();
  load_hosts_from_file("hosts.txt");
  print_hosts();
  cleanup_net();
}

void test_add_host(void)
{
  init_net();
  add_host("127.0.0.1");
  print_hosts();
  cleanup_net();
}

void test_recv_advertisement_broadcast(void)
{
  init_net();
  add_host("127.0.0.1");
  AdvertisementMessage message;
  message.hops = 0;
  message.type = ADVERTISEMENT;
  message.advertisement_type = BROADCAST;
  strcpy(message.source_addr, "56.56.56.56");
  strcpy(message.target_addr, "192.168.1.99");
  recv_advertisement_broadcast(&message);
  cleanup_net();
}

int main(void)
{
  const struct CMUnitTest tests[] =
    {
      cmocka_unit_test(init_net_valid),
      cmocka_unit_test(cleanup_net_valid),
      cmocka_unit_test(send_recv_valid),
      cmocka_unit_test(remove_me),
      cmocka_unit_test(get_ip_address),
    };

  cmocka_run_group_tests(tests, NULL, NULL);

  printf("=============[ Non cmocka Tests ]==============\n");
  printf("[ RUN      ] send_advertisement_broadcast\n");
  send_advertisement_broadcast();

  printf("[ RUN      ] send_advertisement_ack\n");
  send_advertisement_ack();

  printf("[ RUN      ] send_advertisement_reject\n");
  send_advertisement_reject();

  printf("[ RUN      ] test_load_hosts_from_file\n");
  test_load_hosts_from_file();

  printf("[ RUN      ] test_print_hosts\n");
  test_print_hosts();

  printf("[ RUN      ] test_add_host\n");
  test_add_host();

  printf("[ RUN      ] test_recv_advertisement_broadcast\n");
  test_recv_advertisement_broadcast();
  
  return 0;
}
