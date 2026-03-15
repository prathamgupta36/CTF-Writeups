#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t get_size();
void read_all(char *buffer, size_t size);

__attribute__((constructor)) void init() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf("Welcome to the challenge!\n");
}

size_t get_size() {
  char size_buffer[0x40];
  fgets(size_buffer, 0x40, stdin);
  return atol(size_buffer);
}

int main() {
  size_t size = get_size();

  char buffer[size + 1];
  read_all(buffer, size);

  printf("bye! %s\n", buffer);
}

void read_all(char *buffer, size_t size) {
  size_t num_read = 0;
  while (num_read != size)
    num_read += read(0, &buffer[num_read], size - num_read);

  buffer[size] = '\0';
}
