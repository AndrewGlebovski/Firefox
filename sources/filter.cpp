/**
 * \file
 * \brief Contains Filter function implementation.
*/

// ============================================================================

#include <linux/if_packet.h>    // sockaddr_ll
#include <net/ethernet.h>       // ETH_P_ALL
#include <sys/socket.h>         // socket, bind
#include <net/if.h>             // if_nametoindex
#include <assert.h>             // assert
#include <stdio.h>              // printf
#include <arpa/inet.h>          // htons, inet_pton, iphdr
#include <linux/tcp.h>          // tcphdr
#include <linux/udp.h>          // udphdr

#include <filter.hpp>

// ============================================================================

void PrintIp(in_addr_t ip) {
  char str[INET_ADDRSTRLEN] = "";
  inet_ntop(AF_INET, &ip, str, INET_ADDRSTRLEN);

  printf("%s", str);
}

void PrintPort(in_port_t port) {
  printf("%hu", ntohs(port));
}

void PrintPackage(const char* package) {
  size_t offset = sizeof(ether_header);
  auto ip_hdr = reinterpret_cast<const iphdr*>(package + offset);

  if (ip_hdr->protocol == int(Rule::Protocol::TCP)) {
    auto tcp_hdr = reinterpret_cast<const tcphdr*>(package + offset);

    printf("Received TCP package from ");
    PrintIp(ip_hdr->saddr);
    putchar(':');
    PrintPort(tcp_hdr->source);
    printf(" to ");
    PrintIp(ip_hdr->daddr);
    putchar(':');
    PrintPort(tcp_hdr->dest);
    printf(". ");
  } else if (ip_hdr->protocol == int(Rule::Protocol::UDP)) {
    auto udp_hdr = reinterpret_cast<const udphdr*>(package + offset);

    printf("Received UDP package from ");
    PrintIp(ip_hdr->saddr);
    putchar(':');
    PrintPort(udp_hdr->source);
    printf(" to ");
    PrintIp(ip_hdr->daddr);
    putchar(':');
    PrintPort(udp_hdr->dest);
    printf(". ");
  } else if (ip_hdr->protocol == int(Rule::Protocol::ICMP)) {
    printf("Received ICMP package from ");
    PrintIp(ip_hdr->saddr);
    printf(" to ");
    PrintIp(ip_hdr->daddr);
    printf(". ");
  }
}

// ============================================================================

const size_t BUFFER_SIZE = 4 * (1 << 10);

// ============================================================================

int CreateSocket(const char* if_name) {
  int s = socket(AF_PACKET, SOCK_RAW, 0);
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

  auto ether_hdr = reinterpret_cast<ether_header*>(buffer);
  uint16_t type = ntohs(ether_hdr->ether_type);
  
  if (type == ETHERTYPE_IP || type == ETHERTYPE_VLAN) {
    PrintPackage(buffer);

    bool match = (list.Match(buffer) != nullptr);

    if ((list.IsWhite() && !match) || (!list.IsWhite() && match)) {
      printf("Packaged dropped.\n");
      return false;
    }

    printf("Packaged passed.\n");
  } else {
    printf("Package skipped.\n");
  }

  ssize_t write_result = send(out, buffer, read_result, 0);
  assert(read_result == write_result);

  return true;
}
