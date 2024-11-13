/**
 * \file
 * \brief Contains list of rules implementation.
*/

// ============================================================================

#include <net/ethernet.h>     // ether_header
#include <linux/tcp.h>        // tcphdr
#include <linux/udp.h>        // udphdr
#include <sys/mman.h>         // mmap, munmap
#include <assert.h>           // assert
#include <fcntl.h>            // open, flags
#include <unistd.h>           // close
#include <sys/stat.h>         // fstat
#include <stdio.h>            // sscanf
#include <string.h>           // strcmp
#include <arpa/inet.h>        // htons, inet_pton, iphdr

#include <list.hpp>

// ============================================================================

bool ReadListType(char** ptr) {
  char buffer[] = "white";

  int offset = 0;

  sscanf(*ptr, "%5s\n%n", buffer, &offset);
  *ptr += offset;

  if (strcmp(buffer, "white") == 0) {
    return  true;
  }
  
  if (strcmp(buffer, "black") == 0) {
    return false;
  }
  
  assert(false);
}

Rule ReadRule(char** ptr) {
  char daddr[] = "255.255.255.255";
  char dport[] = "65000";
  char saddr[] = "255.255.255.255";
  char sport[] = "65000";
  char prot[] = "icmp";

  int offset = 0;

  sscanf(*ptr, "%s %s %s %s %s\n%n", daddr, dport, saddr, sport, prot, &offset);
  *ptr += offset;

  Rule new_rule = {};

  assert(inet_pton(AF_INET, daddr, &new_rule.dst_ip));
  
  new_rule.dst_port = htons(atoi(dport));

  assert(inet_pton(AF_INET, saddr, &new_rule.src_ip));
  
  new_rule.src_port = htons(atoi(sport));

  if (strcmp(prot, "any") == 0) {
    new_rule.protocol = Rule::Protocol::ANY;
  } else if (strcmp(prot, "icmp") == 0) {
    new_rule.protocol = Rule::Protocol::ICMP;
  } else if (strcmp(prot, "udp") == 0) {
    new_rule.protocol = Rule::Protocol::UDP;
  } else if (strcmp(prot, "tcp") == 0) {
    new_rule.protocol = Rule::Protocol::TCP;
  } else {
    assert(false);
  }

  return new_rule;
}

// ============================================================================

bool Rule::Match(const char* package) const {
  size_t offset = sizeof(ether_header);
  auto ip_hdr = reinterpret_cast<const iphdr*>(package + offset);
  
  if (dst_ip > 0) {
    if (dst_ip != ip_hdr->daddr) {
      return false;
    }
  }

  if (src_ip > 0) {
    if (src_ip != ip_hdr->saddr) {
      return false;
    }
  }

  if (protocol != Protocol::ANY) {
    if (int(protocol) != ip_hdr->protocol) {
      return false;
    }
  }

  offset += sizeof(ip_hdr) + ip_hdr->ihl;

  if (ip_hdr->protocol == int(Protocol::TCP)) {
    auto tcp_hdr = reinterpret_cast<const tcphdr*>(package + offset);

    if (src_port > 0) {
      if (src_port != tcp_hdr->source) {
        return false;
      }
    }

    if (dst_port > 0) {
      if (dst_port != tcp_hdr->dest) {
        return false;
      }
    }
  } else if (ip_hdr->protocol == int(Protocol::UDP)) {
    auto udp_hdr = reinterpret_cast<const udphdr*>(package + offset);

    if (src_port > 0) {
      if (src_port != udp_hdr->source) {
        return false;
      }
    }

    if (dst_port > 0) {
      if (dst_port != udp_hdr->dest) {
        return false;
      }
    }
  }

  return true;
}

// ============================================================================

void List::Read(const char* filename) {
  int fd = open(filename, O_RDONLY);
  assert(fd != -1);

  struct stat info = {};
  assert(fstat(fd, &info) == 0);

  off_t size = info.st_size;

  char* base = (char*) mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  
  assert(base != MAP_FAILED);
  assert(close(fd) == 0);

  char* curr = base;

  is_white_ = ReadListType(&curr);

  while (curr - base < size) {
    ReadRule(&curr);
  }

  assert(munmap(base, size) == 0);
}

void List::AddRule(const Rule& rule) {
  rules_.push_back(rule);
}

const Rule* List::Match(const char* package) const {
  for (const Rule& rule : rules_) {
    if (rule.Match(package)) {
      return &rule;
    }
  }

  return nullptr;
}

bool List::IsWhite() const {
  return is_white_;
}
