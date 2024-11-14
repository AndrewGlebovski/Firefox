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
#include <ctype.h>            // isspace

#include <list.hpp>

// ============================================================================

#define ASSERT(condition, ...)  \
do {                            \
  if (!(condition)) {           \
    printf(__VA_ARGS__);        \
    exit(1);                    \
  }                             \
} while(0)

// ============================================================================

class ConfigParser {
 public:
  ConfigParser(const char* str) : str_(str) {}

  // Non-Copyable and Non-Movable
  ConfigParser(const ConfigParser&) = delete;
  ConfigParser& operator=(const ConfigParser&) = delete;

  bool ParseListType() {
    SkipSpaces();
    
    if (strncasecmp(str_, "white", 5) == 0) {
      str_ += 5;
      return  true;
    }
    
    if (strncasecmp(str_, "black", 5) == 0) {
      str_ += 5;
      return false;
    }

    ASSERT(false, "Wrong config: expected 'black' or 'white'.\n");
  }

  std::vector<Rule> ParseRules() {
    std::vector<Rule> rules;
    
    SkipSpaces();

    ASSERT(Next() == '[', "Wrong config: '[' expected.\n");

    SkipSpaces();

    if (Get() == ']') {
      Next();
      return rules;
    }

    do {
      rules.push_back(ParseRule());
      SkipSpaces();
    } while (Next() == ',');

    ASSERT(str_[-1] == ']', "Wrong config: ',' or ']' expected.\n");

    return rules;
  }

 private:
  Rule ParseRule() {
    Rule new_rule = {};

    SkipSpaces();
    ASSERT(Next() == '{', "Wrong config: '{' expected.\n");
    
    SkipSpaces();

    if (Get() == '}') {
      Next();
      return new_rule;
    }

    do {
      ParseOption(new_rule);
      SkipSpaces();
    } while (Next() == ',');
    
    ASSERT(str_[-1] == '}', "Wrong config: '}' or ',' expected.\n");

    return new_rule;
  }

  void ParseOption(Rule& rule) {
    SkipSpaces();

    const char* name = str_;
    size_t name_size = 0;

    for (; isalnum(name[name_size]); name_size++);

    str_ += name_size;

    SkipSpaces();
    ASSERT(Next() == ':', "Wrong config: ':' expected.\n");

    SkipSpaces();

    char value[32];
    size_t value_size = 0;

    for (; isalnum(str_[value_size]) || str_[value_size] == '.'; value_size++) {
      value[value_size] = str_[value_size];
    }

    value[value_size] = '\0';
    str_ += value_size;

    // ??? Hash map probably ??? Nah, need to allocate std::string
    if (strncasecmp(name, "srcIp", name_size) == 0) {
      ASSERT(inet_pton(AF_INET, value, &rule.src_ip), "Wrong config: srcIp is invalid.\n");
    } else if (strncasecmp(name, "srcPort", name_size) == 0) {
      rule.src_port = htons(atoi(value));
    } else if (strncasecmp(name, "dstIp", name_size) == 0) {
      ASSERT(inet_pton(AF_INET, value, &rule.dst_ip), "Wrong config: dstIp is invalid.\n");
    } else if (strncasecmp(name, "dstPort", name_size) == 0) {
      rule.dst_port = htons(atoi(value));
    } else if (strncasecmp(name, "prot", name_size) == 0) {
      if (strcasecmp(value, "any") == 0) {
        rule.protocol = Rule::Protocol::ANY;
      } else if (strcasecmp(value, "icmp") == 0) {
        rule.protocol = Rule::Protocol::ICMP;
      } else if (strcasecmp(value, "udp") == 0) {
        rule.protocol = Rule::Protocol::UDP;
      } else if (strcasecmp(value, "tcp") == 0) {
        rule.protocol = Rule::Protocol::TCP;
      } else {
        ASSERT(false, "Wrong config: unknown protocol.\n");
      }
    }
  }
  
  void SkipSpaces() {
    for (; isspace(*str_); str_++);
  }

  char Get() const {
    return *str_;
  }

  char Next() {
    return *str_++;
  }
  
  const char* str_ = nullptr;
};

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

void Rule::Dump() const {
  char srcIp[INET_ADDRSTRLEN] = "";
  inet_ntop(AF_INET, &src_ip, srcIp, INET_ADDRSTRLEN);

  in_port_t srcPort = ntohs(src_port);

  char dstIp[INET_ADDRSTRLEN] = "";
  inet_ntop(AF_INET, &dst_ip, dstIp, INET_ADDRSTRLEN);

  in_port_t dstPort = ntohs(dst_port);

  char prot[] = "icmp";

  switch (protocol) {
    case Protocol::ANY: strcpy(prot, "any"); break;
    case Protocol::TCP: strcpy(prot, "tcp"); break;
    case Protocol::UDP: strcpy(prot, "udp"); break;
    default: break;
  }

  printf("{srcIp: %s, srcPort: %hu, dstIp: %s, dstPort: %hu, prot: %s}",
    srcIp, srcPort, dstIp, dstPort, prot);
}

// ============================================================================

void List::Read(const char* filename) {
  int fd = open(filename, O_RDONLY);
  ASSERT(fd != -1, "Failed to open config file.\n");

  struct stat info = {};
  ASSERT(fstat(fd, &info) == 0, "Failed to stat config file.\n");

  off_t size = info.st_size;

  char* base = (char*) mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  ASSERT(base != MAP_FAILED, "Failed to map config file.\n");
  
  ASSERT(close(fd) == 0, "Failed to close config file.\n");

  ConfigParser parser(base);

  is_white_ = parser.ParseListType();

  rules_ = parser.ParseRules();

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

void List::Dump() const {
  if (IsWhite()) {
    printf("white ");
  } else {
    printf("black ");
  }

  putchar('[');

  if (rules_.size() > 0) {
    rules_[0].Dump();

    for (size_t i = 1; i < rules_.size(); i++) {
      putchar(',');
      putchar(' ');
      rules_[i].Dump();
    }
  }
  
  putchar(']');
}
