/**
 * \file
 * \brief Contains Filter function implementation.
*/

// ============================================================================

#include <linux/if_packet.h>    // sockaddr_ll
#include <net/ethernet.h>       // ETH_P_IP, ETH_P_8021Q
#include <sys/socket.h>         // socket, bind
#include <net/if.h>             // if_nametoindex
#include <assert.h>             // assert

#include <filter.hpp>

// ============================================================================

const size_t BUFFER_SIZE = 4 * (1 << 10);

// ============================================================================

int CreateSocket(const char* if_name) {
  int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP | ETH_P_8021Q));
  assert(s != -1);

  struct sockaddr_ll addr = {};

  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = if_nametoindex(if_name);

  bind(s, (sockaddr*) &addr, sizeof(addr));

  return s;
}

bool Filter(int in, int out, const List& list) {
  char buffer[BUFFER_SIZE];

  ssize_t read_result = recv(in, buffer, BUFFER_SIZE, 0);
  assert(read_result != -1);

  bool match = (list.Match(buffer) != nullptr);

  if ((list.IsWhite() && !match) || (!list.IsWhite() && match)) {
    return false;
  }

  ssize_t write_result = send(out, buffer, read_result, 0);
  assert(read_result == write_result);

  return true;
}
