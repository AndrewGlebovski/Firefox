/**
 * \file
 * \brief Contains list of rules declaration.
*/

#pragma once

// ============================================================================

#include <netinet/ip.h>

#include <vector>

// ============================================================================

/// Warning: ip packages only.
struct Rule {
  enum class Protocol {
    ANY   = 0,
    ICMP  = 1,
    TCP   = 6,
    UDP   = 17,
  };

  in_addr_t dst_ip = 0;
  in_port_t dst_port = 0;
  
  in_addr_t src_ip = 0;
  in_port_t src_port = 0;

  Protocol protocol = Protocol::ANY;

  bool Match(const char* package) const;
};

// ============================================================================

class List {
 public:
  /// Reads rules from configuration file. 
  void Read(const char* filename);

  /// Adds rule manually.
  void AddRule(const Rule& rule);

  /// Return matching rule or nullptr. 
  const Rule* Match(const char* package) const;

  /// Returns true if list is white. 
  bool IsWhite() const;

 private:
  std::vector<Rule> rules_;
  bool is_white_;
};
