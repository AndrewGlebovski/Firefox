/**
 * \file
 * \brief Contains main function.
*/

// ============================================================================

#include <stdio.h>    // printf

#include <thread>

#include <filter.hpp>

// ============================================================================

int main(int argc, char* argv[]) {
  if (argc != 2) {
    printf("Usage: <path-to-config-file>\n");
    return 1;
  }

  List list;

  list.Read(argv[1]);

  int in = CreateSocket("eth0");
  int out = CreateSocket("eth1");

  std::thread thread([&](){
    while (true) {
      Filter(in, out, list);
    }
  });

  while (true) {
    Filter(out, in, list);
  }

  return 0;
}
