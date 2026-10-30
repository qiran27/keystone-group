#include "media-source.h"

#include <limits.h>
#include <string.h>

static int next_number(const uint8_t* input, size_t bytes, size_t* position,
                       unsigned* output) {
  unsigned value = 0;
  size_t p = *position;
  while (p < bytes) {
    if (input[p] == '#') {
      while (p < bytes && input[p] != '\n') ++p;
    } else if (input[p] == ' ' || input[p] == '\n' || input[p] == '\r' ||
               input[p] == '\t') {
      ++p;
    } else break;
  }
  if (p == bytes || input[p] < '0' || input[p] > '9') return -1;
  while (p < bytes && input[p] >= '0' && input[p] <= '9') {
    if (value > (UINT_MAX - (unsigned)(input[p] - '0')) / 10) return -1;
    value = value * 10 + (unsigned)(input[p++] - '0');
  }
  *position = p;
  *output = value;
  return 0;
}

static uint8_t clamp8(int value) {
  return (uint8_t)(value < 0 ? 0 : value > 255 ? 255 : value);
}

int group_pmp_media_ppm_to_yuv420(const uint8_t* ppm, size_t ppm_bytes,
    uint8_t* yuv, size_t yuv_capacity, unsigned* width, unsigned* height) {
  size_t position = 2;
  size_t pixels;
  unsigned w, h, maximum;
  unsigned row, column;
  if (!ppm || !yuv || !width || !height || ppm_bytes < 16 ||
      memcmp(ppm, "P6", 2) != 0 ||
      next_number(ppm, ppm_bytes, &position, &w) != 0 ||
      next_number(ppm, ppm_bytes, &position, &h) != 0 ||
      next_number(ppm, ppm_bytes, &position, &maximum) != 0 ||
      !w || !h || (w & 1U) || (h & 1U) || maximum != 255 ||
      position >= ppm_bytes ||
      (ppm[position] != ' ' && ppm[position] != '\n' &&
       ppm[position] != '\r' && ppm[position] != '\t') ||
      (size_t)w > SIZE_MAX / h) return -1;
  ++position;
  pixels = (size_t)w * h;
  if (pixels > SIZE_MAX / 3 || pixels * 3 > ppm_bytes - position ||
      pixels > SIZE_MAX / 3 * 2 || pixels + pixels / 2 > yuv_capacity)
    return -1;
  for (row = 0; row < h; ++row)
    for (column = 0; column < w; ++column) {
      size_t index = (size_t)row * w + column;
      const uint8_t* rgb = ppm + position + index * 3;
      int r = rgb[0], g = rgb[1], b = rgb[2];
      yuv[index] = clamp8((77 * r + 150 * g + 29 * b + 128) >> 8);
    }
  for (row = 0; row < h; row += 2)
    for (column = 0; column < w; column += 2) {
      int u = 0, v = 0;
      unsigned dy, dx;
      size_t chroma = (size_t)(row / 2) * (w / 2) + column / 2;
      for (dy = 0; dy < 2; ++dy)
        for (dx = 0; dx < 2; ++dx) {
          size_t index = (size_t)(row + dy) * w + column + dx;
          const uint8_t* rgb = ppm + position + index * 3;
          int r = rgb[0], g = rgb[1], b = rgb[2];
          u += ((-43 * r - 85 * g + 128 * b + 128) >> 8) + 128;
          v += ((128 * r - 107 * g - 21 * b + 128) >> 8) + 128;
        }
      yuv[pixels + chroma] = clamp8((u + 2) / 4);
      yuv[pixels + pixels / 4 + chroma] = clamp8((v + 2) / 4);
    }
  *width = w;
  *height = h;
  return 0;
}

static uint32_t le32(const uint8_t* data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
      ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

int group_pmp_media_avi_first_mpeg4(const uint8_t* avi, size_t avi_bytes,
    const uint8_t** packet, size_t* packet_bytes,
    unsigned* width, unsigned* height) {
  size_t p;
  int have_dimensions = 0;
  if (!avi || !packet || !packet_bytes || !width || !height ||
      avi_bytes < 64 || memcmp(avi, "RIFF", 4) != 0 ||
      memcmp(avi + 8, "AVI ", 4) != 0) return -1;
  for (p = 12; p + 32 <= avi_bytes; ++p)
    if (memcmp(avi + p, "avih", 4) == 0 &&
        le32(avi + p + 4) >= 40 && p + 48 <= avi_bytes) {
      *width = le32(avi + p + 40);
      *height = le32(avi + p + 44);
      have_dimensions = *width && *height && !(*width & 1U) &&
          !(*height & 1U);
      break;
    }
  if (!have_dimensions) return -1;
  for (p = 12; p + 12 <= avi_bytes; ++p)
    if (memcmp(avi + p, "LIST", 4) == 0 &&
        memcmp(avi + p + 8, "movi", 4) == 0) {
      size_t end;
      size_t cursor = p + 12;
      uint32_t length = le32(avi + p + 4);
      if (length < 4 || length - 4 > avi_bytes - cursor) return -1;
      end = cursor + length - 4;
      while (cursor + 8 <= end) {
        uint32_t chunk = le32(avi + cursor + 4);
        size_t start = cursor + 8;
        if (chunk > end - start) return -1;
        if (avi[cursor] >= '0' && avi[cursor] <= '9' &&
            avi[cursor + 1] >= '0' && avi[cursor + 1] <= '9' &&
            avi[cursor + 2] == 'd' && avi[cursor + 3] == 'c' && chunk) {
          *packet = avi + start;
          *packet_bytes = chunk;
          return 0;
        }
        cursor = start + chunk + (chunk & 1U);
      }
      return -1;
    }
  return -1;
}
