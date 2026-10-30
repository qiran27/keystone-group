#include <edge_call.h>
#include <keystone.h>

extern "C" {
#include "group-pmp-crypto.h"
#include "media-board-files.h"
#include "media-store.h"
}

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {
const uint8_t kMediaKey[16] = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x11, 0x33, 0x55, 0x77, 0x99, 0xbb, 0xdd, 0xff};

struct BoardContext {
  uint64_t codec = 0;
  std::string input_dir;
  std::string output_dir;
  const group_pmp_media_board_file* specs = nullptr;
  size_t count = 0;
  group_pmp_media_host_file files[GROUP_PMP_MEDIA_BOARD_MAX_FILES] = {};
  uint64_t next_sequence[GROUP_PMP_MEDIA_BOARD_MAX_FILES] = {};
  uint64_t written_bytes[GROUP_PMP_MEDIA_BOARD_MAX_FILES] = {};
  bool last_chunk[GROUP_PMP_MEDIA_BOARD_MAX_FILES] = {};
  bool done = false;
  uint64_t output_bytes = 0;
  size_t utm_size = 0;
};
BoardContext* current = nullptr;

const char* codec_name(uint64_t codec) {
  switch (codec) {
    case GROUP_PMP_MEDIA_MPEG4_ENCODE: return "mpeg4enc";
    case GROUP_PMP_MEDIA_MPEG4_DECODE: return "mpeg4dec";
    case GROUP_PMP_MEDIA_JP2_ENCODE: return "jpg2000enc";
    case GROUP_PMP_MEDIA_JP2_DECODE: return "jpg2000dec";
    case GROUP_PMP_MEDIA_H264_ENCODE: return "h264enc";
    case GROUP_PMP_MEDIA_H264_DECODE: return "h264dec";
    default: return nullptr;
  }
}

uint64_t parse_codec(const char* text) {
  for (uint64_t codec = GROUP_PMP_MEDIA_MPEG4_ENCODE;
       codec <= GROUP_PMP_MEDIA_H264_DECODE; ++codec)
    if (std::strcmp(text, codec_name(codec)) == 0) return codec;
  return 0;
}

std::string path_for(const std::string& directory, const char* name) {
  return directory + "/" + name + ".cipher";
}

void close_files(BoardContext* context) {
  for (size_t i = 0; i < context->count; ++i)
    if (context->files[i].file)
      group_pmp_media_host_close(&context->files[i]);
}

int stage_inputs(uint64_t codec, const std::string& input_dir,
                 const std::string& encrypted_dir) {
  size_t count = 0;
  const group_pmp_media_board_file* specs =
      group_pmp_media_board_files(codec, &count);
  group_pmp_crypto_context crypto = {};
  if (!specs || group_pmp_crypto_init(&crypto, GROUP_PMP_CRYPTO_AES_128_ECB,
                                     kMediaKey, sizeof(kMediaKey)) != 0)
    return 1;
  std::vector<uint8_t> utm(GROUP_PMP_MEDIA_DATA_BUFFER_BYTES);
  for (size_t i = 0; i < count; ++i) {
    if (specs[i].writable) continue;
    const std::string source = input_dir + "/" + specs[i].name;
    const std::string destination = path_for(encrypted_dir, specs[i].name);
    FILE* file = std::fopen(source.c_str(), "rb");
    if (!file || std::fseek(file, 0, SEEK_END) != 0) {
      if (file) std::fclose(file);
      group_pmp_crypto_deinit(&crypto);
      std::fprintf(stderr, "[media] cannot read %s\n", source.c_str());
      return 1;
    }
    const long length = std::ftell(file);
    if (length <= 0 || static_cast<uint64_t>(length) > specs[i].capacity ||
        std::fseek(file, 0, SEEK_SET) != 0) {
      std::fclose(file);
      group_pmp_crypto_deinit(&crypto);
      std::fprintf(stderr, "[media] invalid input size: %s\n", source.c_str());
      return 1;
    }
    std::vector<uint8_t> plain(static_cast<size_t>(length));
    if (std::fread(plain.data(), 1, plain.size(), file) != plain.size()) {
      std::fclose(file);
      group_pmp_crypto_deinit(&crypto);
      return 1;
    }
    std::fclose(file);
    group_pmp_media_host_file host = {};
    if (group_pmp_media_host_open(&host, destination.c_str(), 1) != 0 ||
        group_pmp_media_write_stream(&crypto, codec, i + 1, 1, 1,
                                     plain.data(), plain.size(), utm.data(),
                                     utm.size(), group_pmp_media_host_publish,
                                     &host) != 0 ||
        group_pmp_media_host_close(&host) != 0) {
      if (host.file) group_pmp_media_host_close(&host);
      group_pmp_crypto_deinit(&crypto);
      return 1;
    }
    std::memset(plain.data(), 0, plain.size());
    std::printf("[media] staged ciphertext input=%s bytes=%ld\n",
                destination.c_str(), length);
  }
  group_pmp_crypto_deinit(&crypto);
  return 0;
}

void media_ocall(void* buffer) {
  auto* call = static_cast<edge_call*>(buffer);
  uintptr_t args = 0;
  size_t args_size = 0;
  group_pmp_media_board_reply reply = {};
  reply.status = -1;
  if (!current || !buffer ||
      edge_call_args_ptr(call, &args, &args_size) != 0 ||
      args_size != sizeof(group_pmp_media_board_request)) {
    call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  group_pmp_media_board_request request;
  std::memcpy(&request, reinterpret_cast<const void*>(args), sizeof(request));
  if (request.magic != GROUP_PMP_MEDIA_BOARD_MAGIC ||
      request.version != GROUP_PMP_MEDIA_BOARD_VERSION ||
      request.utm_offset != GROUP_PMP_MEDIA_BOARD_UTM_DATA_OFFSET ||
      (request.operation != GROUP_PMP_MEDIA_BOARD_CONFIG &&
       request.codec != current->codec))
    goto publish;
  if (request.operation == GROUP_PMP_MEDIA_BOARD_CONFIG) {
    reply.codec = current->codec;
    reply.status = 0;
  } else if (request.operation == GROUP_PMP_MEDIA_BOARD_DONE) {
    uint64_t bytes = 0;
    const size_t required_output = current->codec >= GROUP_PMP_MEDIA_H264_ENCODE ? 4 : 1;
    for (size_t i = 0; i < current->count; ++i) {
      if (current->written_bytes[i] && !current->last_chunk[i]) goto publish;
      bytes += current->written_bytes[i];
    }
    if (!current->last_chunk[required_output] || !bytes ||
        request.output_bytes != bytes) goto publish;
    current->output_bytes = bytes;
    current->done = true;
    reply.status = 0;
  } else if (request.file_id < current->count &&
             request.task_id == request.file_id + 1 &&
             !current->done &&
             current->utm_size >= GROUP_PMP_MEDIA_BOARD_UTM_BYTES) {
    const size_t id = static_cast<size_t>(request.file_id);
    const group_pmp_media_board_file& spec = current->specs[id];
    const std::string path = path_for(
        spec.writable ? current->output_dir : current->input_dir, spec.name);
    uint8_t* utm = static_cast<uint8_t*>(buffer) + request.utm_offset;
    if (request.operation == GROUP_PMP_MEDIA_BOARD_READ && !spec.writable) {
      if (!current->files[id].file &&
          group_pmp_media_host_open(&current->files[id], path.c_str(), 0) != 0)
        goto publish;
      if (group_pmp_media_host_receive(&current->files[id], &reply.frame,
              utm, GROUP_PMP_MEDIA_DATA_BUFFER_BYTES) != 0)
        goto publish;
      reply.status = 0;
    } else if (request.operation == GROUP_PMP_MEDIA_BOARD_WRITE &&
               spec.writable && !current->last_chunk[id] &&
               group_pmp_media_frame_valid(&request.frame) &&
               request.frame.codec == current->codec &&
               request.frame.task_id == id + 1 &&
               request.frame.key_epoch == 1 &&
               request.frame.sequence == current->next_sequence[id] + 1 &&
               request.frame.chunk_offset == current->written_bytes[id] &&
               request.frame.frame_bytes <= spec.capacity) {
      if (!current->files[id].file &&
          group_pmp_media_host_open(&current->files[id], path.c_str(), 1) != 0)
        goto publish;
      if (group_pmp_media_host_publish(&current->files[id], &request.frame,
                                       utm) != 0)
        goto publish;
      ++current->next_sequence[id];
      current->written_bytes[id] += request.frame.plain_bytes;
      current->last_chunk[id] = request.frame.final_chunk != 0;
      reply.status = 0;
    }
  }
publish:
  uintptr_t target = edge_call_data_ptr();
  std::memcpy(reinterpret_cast<void*>(target), &reply, sizeof(reply));
  call->return_data.call_status =
      edge_call_setup_ret(call, reinterpret_cast<void*>(target),
                          sizeof(reply)) == 0 ? CALL_STATUS_OK : CALL_STATUS_BAD_PTR;
}

int run_codec(uint64_t codec, const std::string& input_dir,
              const std::string& output_dir, const char* eapp,
              const char* runtime, const char* loader) {
  BoardContext context;
  context.codec = codec;
  context.input_dir = input_dir;
  context.output_dir = output_dir;
  context.specs = group_pmp_media_board_files(codec, &context.count);
  context.utm_size = GROUP_PMP_MEDIA_BOARD_UTM_BYTES;
  if (!context.specs || current || register_call(
          GROUP_PMP_MEDIA_BOARD_OCALL_ID, media_ocall) != 0)
    return 1;
  Keystone::Enclave enclave;
  Keystone::Params params;
  params.setFreeMemSize(64U << 20);
  params.setUntrustedSize(GROUP_PMP_MEDIA_BOARD_UTM_BYTES);
  if (enclave.init(eapp, runtime, loader, params) != Keystone::Error::Success) {
    std::fprintf(stderr, "[media] enclave initialization failed\n");
    return 1;
  }
  enclave.registerOcallDispatch(incoming_call_dispatch);
  if (!enclave.getSharedBuffer() ||
      enclave.getSharedBufferSize() < GROUP_PMP_MEDIA_BOARD_UTM_BYTES)
    return 1;
  edge_call_init_internals(
      reinterpret_cast<uintptr_t>(enclave.getSharedBuffer()),
      enclave.getSharedBufferSize());
  current = &context;
  const auto start = std::chrono::steady_clock::now();
  const Keystone::Error result = enclave.run();
  const auto stop = std::chrono::steady_clock::now();
  current = nullptr;
  close_files(&context);
  if (result != Keystone::Error::Success || !context.done) {
    std::fprintf(stderr, "[media] enclave failed: codec=%s done=%d\n",
                 codec_name(codec), context.done ? 1 : 0);
    return 1;
  }
  const double seconds = std::chrono::duration<double>(stop - start).count();
  std::printf("[media] codec=%s enclave_codec=1 output_plain_bytes=%llu seconds=%.6f\n",
              codec_name(codec),
              static_cast<unsigned long long>(context.output_bytes), seconds);
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 5) {
    std::fprintf(stderr,
        "usage: %s --stage <codec> <input-dir> <cipher-dir>\n"
        "       %s --run <codec> <cipher-dir> <output-dir> [eapp runtime loader]\n",
        argv[0], argv[0]);
    return 2;
  }
  const uint64_t codec = parse_codec(argv[2]);
  if (!codec) return 2;
  if (std::strcmp(argv[1], "--stage") == 0 && argc == 5)
    return stage_inputs(codec, argv[3], argv[4]);
  if (std::strcmp(argv[1], "--run") == 0 && (argc == 5 || argc == 8)) {
    const char* eapp = argc == 8 ? argv[5] :
        codec <= GROUP_PMP_MEDIA_MPEG4_DECODE ?
            "group-pmp-mediabench-mpeg4-board.eapp_riscv" :
        codec <= GROUP_PMP_MEDIA_JP2_DECODE ?
            "group-pmp-mediabench-jp2-board.eapp_riscv" :
        codec == GROUP_PMP_MEDIA_H264_ENCODE ?
            "group-pmp-mediabench-h264-enc-board.eapp_riscv" :
            "group-pmp-mediabench-h264-dec-board.eapp_riscv";
    return run_codec(codec, argv[3], argv[4], eapp,
                     argc == 8 ? argv[6] : "eyrie-rt",
                     argc == 8 ? argv[7] : "loader.bin");
  }
  return 2;
}
