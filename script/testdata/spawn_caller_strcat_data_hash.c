#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ckb_exec.h"
#include "ckb_syscalls.h"

int main() {
  const char *argv[] = {"hello", "world"};
  int8_t exit_code = 255;
  uint8_t content[80] = {};
  uint64_t content_length = 80;
  uint8_t hash[32] = {};
  _exec_hex2bin(
      "2662a338e7162f105439c91cc2c312775ad79db7e2b924d2391841ac1682b93a", hash,
      32, NULL);
  ckb_spawn_cell(8, hash, 0, 0, 0, 2, argv, &exit_code, &content[0],
                 &content_length);
  if (strlen(content) != 10) {
    return 1;
  }
  if (strcmp(content, "helloworld") != 0) {
    return 1;
  }
  if (exit_code != 0) {
    return 1;
  }
  return 0;
}
