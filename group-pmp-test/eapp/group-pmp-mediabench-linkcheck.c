#include <stdint.h>

#if defined(GROUP_PMP_MEDIABENCH_LINK_MPEG4)
#include "mpeg4-memory.h"
#elif defined(GROUP_PMP_MEDIABENCH_LINK_JP2)
#include "jp2-memory.h"
#elif defined(GROUP_PMP_MEDIABENCH_LINK_IO)
#include "media-io.h"
#else
#include "h264-memory.h"
#endif

int main(void) {
#if defined(GROUP_PMP_MEDIABENCH_LINK_MPEG4) || defined(GROUP_PMP_MEDIABENCH_LINK_JP2) || defined(GROUP_PMP_MEDIABENCH_LINK_IO)
  size_t produced = 0;
#endif
#if defined(GROUP_PMP_MEDIABENCH_LINK_MPEG4)
  return group_pmp_mpeg4_encode_yuv420(0, 0, 16, 16, 0, 0,
                                       &produced) == -1 ? 0 : 1;
#elif defined(GROUP_PMP_MEDIABENCH_LINK_JP2)
  return group_pmp_jp2_encode_ppm(0, 0, 0, 0,
                                  &produced) == -1 ? 0 : 1;
#elif defined(GROUP_PMP_MEDIABENCH_LINK_IO)
  return group_pmp_media_cipher_bytes(17, &produced) == 0 &&
         produced == 32 ? 0 : 1;
#else
  return group_pmp_h264_run_memory(0, 0, 0) == -1 ? 0 : 1;
#endif
}
