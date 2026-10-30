#include <stddef.h>

int strcmp(const char* left, const char* right) {
  const unsigned char* lhs = (const unsigned char*)left;
  const unsigned char* rhs = (const unsigned char*)right;

  while (*lhs && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return (int)*lhs - (int)*rhs;
}

int strncmp(const char* left, const char* right, size_t length) {
  const unsigned char* lhs = (const unsigned char*)left;
  const unsigned char* rhs = (const unsigned char*)right;

  while (length && *lhs && *lhs == *rhs) {
    ++lhs;
    ++rhs;
    --length;
  }
  if (!length)
    return 0;
  return (int)*lhs - (int)*rhs;
}

size_t strcspn(const char* string, const char* reject) {
  size_t length = 0;

  while (string[length]) {
    const char* denied = reject;
    while (*denied) {
      if ((unsigned char)string[length] == (unsigned char)*denied)
        return length;
      ++denied;
    }
    ++length;
  }
  return length;
}
