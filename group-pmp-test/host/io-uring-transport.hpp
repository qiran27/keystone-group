#ifndef GROUP_PMP_IO_URING_TRANSPORT_HPP
#define GROUP_PMP_IO_URING_TRANSPORT_HPP
// Shared SQLite/FIO and motivation transport. Policy, ownership and crypto stay
// with callers; accepted SQEs retain their payload until their individual CQE.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <initializer_list>
#include <stdexcept>
#include <vector>
#ifdef __linux__
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#endif
#endif
namespace GroupIo {
inline uint64_t now_ns() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
}
#ifdef __linux__
inline uint64_t thread_cpu_ns() {
  struct timespec value;
  return clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) == 0 ?
      static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
          static_cast<uint64_t>(value.tv_nsec) : 0;
}
#endif
template <typename T>
class InlineOneList {
 public:
  InlineOneList& operator=(std::initializer_list<T> values) {
    clear();
    reserve(values.size());
    for (const T& value : values) push_back(value);
    return *this;
  }
  size_t size() const { return many_.empty() ? (has_one_ ? 1 : 0) : many_.size(); }
  bool empty() const { return size() == 0; }
  T* data() { return many_.empty() ? &one_ : many_.data(); }
  const T* data() const { return many_.empty() ? &one_ : many_.data(); }
  T* begin() { return data(); }
  T* end() { return data() + size(); }
  const T* begin() const { return data(); }
  const T* end() const { return data() + size(); }
  T& operator[](size_t index) { return data()[index]; }
  const T& operator[](size_t index) const { return data()[index]; }
  T& front() { return (*this)[0]; }
  const T& front() const { return (*this)[0]; }
  void reserve(size_t count) { if (count > 1) many_.reserve(count); }
  void clear() { has_one_ = false; many_.clear(); }
  void push_back(const T& value) {
    if (!has_one_) { one_ = value; has_one_ = true; return; }
    if (many_.empty()) many_.push_back(one_);
    many_.push_back(value);
  }
  template <typename It>
  void insert(T* position, It first, It last) {
    if (position != end()) throw std::logic_error("InlineOneList only supports append");
    for (; first != last; ++first) push_back(*first);
  }
 private:
  T one_{};
  bool has_one_ = false;
  std::vector<T> many_;
};

#ifdef __linux__
class RawIoUring {
 public:
  struct SubmitTiming {
    uint64_t prep_wall_ns = 0, prep_cpu_ns = 0;
    uint64_t enter_wall_ns = 0, enter_cpu_ns = 0;
    uint64_t voluntary_switches = 0, involuntary_switches = 0;
    uint64_t output_blocks = 0;
  };

  struct Operation {
    int fd;
    int fixed_file_index;
    int fixed_buffer_index;
    uint64_t offset;
    InlineOneList<struct iovec>* vectors;
    uint64_t expected;
    bool read;

    Operation()
        : fd(-1), fixed_file_index(-1), fixed_buffer_index(-1), offset(0),
          vectors(nullptr), expected(0), read(false) {}
  };

  explicit RawIoUring(unsigned capacity = 1024)
      : capacity_(capacity), fd_(-1), sq_ptr_(MAP_FAILED), cq_ptr_(MAP_FAILED),
        sqes_(MAP_FAILED), sq_size_(0), cq_size_(0), sqes_size_(0),
        sq_head_(nullptr), sq_tail_(nullptr), sq_mask_(nullptr),
        sq_entries_(nullptr), sq_array_(nullptr), cq_head_(nullptr),
        cq_tail_(nullptr), cq_mask_(nullptr), cqes_(nullptr) {}

  ~RawIoUring() { close_ring(); }

  bool registerFiles(const std::vector<int>& files) {
    if (!available())
      return false;
    if (files == registered_files_)
      return !registered_files_.empty();
    if (stream_inflight_) return false;
    unregisterFiles();
    if (files.empty())
      return true;
    int result = static_cast<int>(syscall(
        __NR_io_uring_register, fd_, IORING_REGISTER_FILES,
        files.data(), static_cast<unsigned>(files.size())));
    if (result < 0)
      return false;
    registered_files_ = files;
    return true;
  }

  bool registerBuffers(const std::vector<struct iovec>& buffers) {
    if (!available())
      return false;
    if (sameBuffers(buffers))
      return !registered_buffers_.empty();
    if (stream_inflight_) return false;
    unregisterBuffers();
    if (buffers.empty())
      return true;
    int result = static_cast<int>(syscall(
        __NR_io_uring_register, fd_, IORING_REGISTER_BUFFERS,
        buffers.data(), static_cast<unsigned>(buffers.size())));
    if (result < 0)
      return false;
    registered_buffers_ = buffers;
    return true;
  }

  void unregisterBuffers() {
    if (stream_inflight_) return;
    if (fd_ >= 0 && !registered_buffers_.empty())
      (void)syscall(__NR_io_uring_register, fd_,
                    IORING_UNREGISTER_BUFFERS, nullptr, 0);
    registered_buffers_.clear();
  }

  bool available() {
    if (fd_ >= 0)
      return true;
    struct io_uring_params params;
    std::memset(&params, 0, sizeof(params));
    fd_ = static_cast<int>(syscall(__NR_io_uring_setup,
                                   capacity_, &params));
    if (fd_ < 0)
      return false;
    sq_size_ = params.sq_off.array +
        params.sq_entries * sizeof(unsigned);
    cq_size_ = params.cq_off.cqes +
        params.cq_entries * sizeof(struct io_uring_cqe);
    if (params.features & IORING_FEAT_SINGLE_MMAP) {
      sq_size_ = std::max(sq_size_, cq_size_);
      cq_size_ = sq_size_;
    }
    sq_ptr_ = mmap(nullptr, sq_size_, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, fd_, IORING_OFF_SQ_RING);
    if (sq_ptr_ == MAP_FAILED) {
      close_ring();
      return false;
    }
    if (params.features & IORING_FEAT_SINGLE_MMAP) {
      cq_ptr_ = sq_ptr_;
    } else {
      cq_ptr_ = mmap(nullptr, cq_size_, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, fd_, IORING_OFF_CQ_RING);
      if (cq_ptr_ == MAP_FAILED) {
        close_ring();
        return false;
      }
    }
    sqes_size_ = params.sq_entries * sizeof(struct io_uring_sqe);
    sqes_ = mmap(nullptr, sqes_size_, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_POPULATE, fd_, IORING_OFF_SQES);
    if (sqes_ == MAP_FAILED) {
      close_ring();
      return false;
    }
    sq_head_ = pointer<unsigned>(sq_ptr_, params.sq_off.head);
    sq_tail_ = pointer<unsigned>(sq_ptr_, params.sq_off.tail);
    sq_mask_ = pointer<unsigned>(sq_ptr_, params.sq_off.ring_mask);
    sq_entries_ = pointer<unsigned>(sq_ptr_, params.sq_off.ring_entries);
    sq_array_ = pointer<unsigned>(sq_ptr_, params.sq_off.array);
    cq_head_ = pointer<unsigned>(cq_ptr_, params.cq_off.head);
    cq_tail_ = pointer<unsigned>(cq_ptr_, params.cq_off.tail);
    cq_mask_ = pointer<unsigned>(cq_ptr_, params.cq_off.ring_mask);
    cqes_ = pointer<struct io_uring_cqe>(cq_ptr_, params.cq_off.cqes);
    return true;
  }

  bool submit(const std::vector<Operation>& operations,
              std::vector<int>* results, uint64_t* submit_ns,
              uint64_t* completion_ns) {
    const uint64_t begin_ns = now_ns();
    uint64_t submitted_ns = begin_ns;
    if (submit_ns)
      *submit_ns = 0;
    if (completion_ns)
      *completion_ns = 0;
    if (stream_inflight_ || !results || operations.empty() || !available() ||
        operations.size() > *sq_entries_)
      return false;
    unsigned head = __atomic_load_n(sq_head_, __ATOMIC_ACQUIRE);
    unsigned tail = *sq_tail_;
    if (operations.size() > *sq_entries_ - (tail - head))
      return false;
    results->assign(operations.size(), -EIO);
    for (size_t index = 0; index < operations.size(); ++index) {
      unsigned slot = (tail + static_cast<unsigned>(index)) & *sq_mask_;
      struct io_uring_sqe* sqe =
          &static_cast<struct io_uring_sqe*>(sqes_)[slot];
      std::memset(sqe, 0, sizeof(*sqe));
      const Operation& operation = operations[index];
      const bool fixed_buffer = operation.fixed_buffer_index >= 0 &&
          operation.vectors && operation.vectors->size() == 1;
      sqe->opcode = fixed_buffer ?
          (operation.read ? IORING_OP_READ_FIXED : IORING_OP_WRITE_FIXED) :
          (operation.read ? IORING_OP_READV : IORING_OP_WRITEV);
      if (operation.fixed_file_index >= 0) {
        sqe->fd = operation.fixed_file_index;
        sqe->flags |= IOSQE_FIXED_FILE;
      } else {
        sqe->fd = operation.fd;
      }
      sqe->off = operation.offset;
      if (fixed_buffer) {
        sqe->addr = reinterpret_cast<uint64_t>(
            (*operation.vectors)[0].iov_base);
        sqe->len = static_cast<uint32_t>((*operation.vectors)[0].iov_len);
        sqe->buf_index = static_cast<uint16_t>(operation.fixed_buffer_index);
      } else {
        sqe->addr = reinterpret_cast<uint64_t>(operation.vectors->data());
        sqe->len = static_cast<uint32_t>(operation.vectors->size());
      }
      sqe->user_data = static_cast<uint64_t>(index + 1);
      sq_array_[slot] = slot;
    }
    __atomic_store_n(sq_tail_, tail + static_cast<unsigned>(operations.size()),
                     __ATOMIC_RELEASE);
    size_t submitted = 0;
    while (submitted < operations.size()) {
      int value;
      do {
        value = static_cast<int>(syscall(
            __NR_io_uring_enter, fd_,
            static_cast<unsigned>(operations.size() - submitted),
            0, 0, nullptr, 0));
      } while (value < 0 && errno == EINTR);
      if (value <= 0)
        break;
      submitted += static_cast<size_t>(value);
    }
    submitted_ns = now_ns();
    if (submit_ns)
      *submit_ns = submitted_ns - begin_ns;
    if (!submitted)
      return false;
    const bool reset_after_completion = submitted != operations.size();

    size_t completed = 0;
    while (completed < submitted) {
      unsigned cq_head = __atomic_load_n(cq_head_, __ATOMIC_ACQUIRE);
      unsigned cq_tail = __atomic_load_n(cq_tail_, __ATOMIC_ACQUIRE);
      if (cq_head == cq_tail) {
        int result;
        do {
          result = static_cast<int>(syscall(
              __NR_io_uring_enter, fd_, 0, 1, IORING_ENTER_GETEVENTS,
              nullptr, 0));
        } while (result < 0 && errno == EINTR);
        if (result < 0)
          return false;
        continue;
      }
      while (cq_head != cq_tail && completed < submitted) {
        const struct io_uring_cqe& cqe = cqes_[cq_head & *cq_mask_];
        if (!cqe.user_data || cqe.user_data > operations.size())
          return false;
        (*results)[static_cast<size_t>(cqe.user_data - 1)] = cqe.res;
        ++cq_head;
        ++completed;
      }
      __atomic_store_n(cq_head_, cq_head, __ATOMIC_RELEASE);
    }
    if (reset_after_completion)
      close_ring();
    if (completion_ns)
      *completion_ns = now_ns() - submitted_ns;
    return true;
  }

  struct Completion { uint64_t token; int result; };

  int descriptor() const { return fd_; }
  size_t inflight() const { return stream_inflight_; }

  // Tokens and iovec/payload storage are owned by the reactor until the CQE.
  // Partial submission is reported precisely; never replay an accepted write.
  size_t submitAsync(const std::vector<Operation>& operations,
                     const std::vector<uint64_t>& tokens, int* error,
                     size_t* enters = nullptr, size_t* partials = nullptr,
                     SubmitTiming* timing = nullptr) {
    *error = 0;
    if (enters) *enters = 0;
    if (partials) *partials = 0;
    if (timing) *timing = SubmitTiming{};
    if (operations.empty() || operations.size() != tokens.size() || !available()) {
      *error = -EINVAL;
      return 0;
    }
    const unsigned head = __atomic_load_n(sq_head_, __ATOMIC_ACQUIRE);
    const unsigned tail = __atomic_load_n(sq_tail_, __ATOMIC_RELAXED);
    if (operations.size() > *sq_entries_ - (tail - head)) {
      *error = -EAGAIN;
      return 0;
    }
    const uint64_t prep_cpu_start = timing ? thread_cpu_ns() : 0;
    const uint64_t prep_wall_start = timing ? now_ns() : 0;
    for (size_t i = 0; i < operations.size(); ++i) {
      const unsigned slot = (tail + static_cast<unsigned>(i)) & *sq_mask_;
      auto* sqe = &static_cast<struct io_uring_sqe*>(sqes_)[slot];
      std::memset(sqe, 0, sizeof(*sqe));
      const auto& op = operations[i];
      const bool fixed = op.fixed_buffer_index >= 0 && op.vectors->size() == 1;
      sqe->opcode = fixed ? (op.read ? IORING_OP_READ_FIXED : IORING_OP_WRITE_FIXED) :
          (op.read ? IORING_OP_READV : IORING_OP_WRITEV);
      sqe->fd = op.fixed_file_index >= 0 ? op.fixed_file_index : op.fd;
      if (op.fixed_file_index >= 0) sqe->flags |= IOSQE_FIXED_FILE;
      sqe->off = op.offset;
      sqe->addr = fixed ? reinterpret_cast<uint64_t>((*op.vectors)[0].iov_base) :
          reinterpret_cast<uint64_t>(op.vectors->data());
      sqe->len = fixed ? static_cast<uint32_t>((*op.vectors)[0].iov_len) :
          static_cast<uint32_t>(op.vectors->size());
      if (fixed) sqe->buf_index = static_cast<uint16_t>(op.fixed_buffer_index);
      sqe->user_data = tokens[i];
      sq_array_[slot] = slot;
    }
    __atomic_store_n(sq_tail_, tail + static_cast<unsigned>(operations.size()), __ATOMIC_RELEASE);
    if (timing) {
      timing->prep_wall_ns = now_ns() - prep_wall_start;
      const uint64_t end = thread_cpu_ns();
      if (prep_cpu_start && end >= prep_cpu_start)
        timing->prep_cpu_ns = end - prep_cpu_start;
    }
    struct rusage usage_before{}, usage_after{};
    const bool usage_valid = timing && getrusage(RUSAGE_THREAD, &usage_before) == 0;
    const uint64_t enter_cpu_start = timing ? thread_cpu_ns() : 0;
    const uint64_t enter_wall_start = timing ? now_ns() : 0;
    size_t accepted = 0;
    while (accepted < operations.size()) {
      if (enters) ++*enters;
      const int result = static_cast<int>(syscall(__NR_io_uring_enter, fd_,
          static_cast<unsigned>(operations.size() - accepted), 0, 0, nullptr, 0));
      if (result < 0 && errno == EINTR) continue;
      if (result <= 0) {
        *error = result < 0 ? -errno : -EIO;
        // No SQPOLL is used: no kernel consumer remains after enter returns.
        // Drop only SQEs that the kernel did not consume, leaving accepted
        // operations alive until their individual CQEs have been reaped.
        accepted = __atomic_load_n(sq_head_, __ATOMIC_ACQUIRE) - tail;
        __atomic_store_n(sq_tail_, tail + static_cast<unsigned>(accepted), __ATOMIC_RELEASE);
        break;
      }
      if (partials && static_cast<size_t>(result) < operations.size() - accepted) ++*partials;
      accepted += static_cast<size_t>(result);
    }
    if (timing) {
      timing->enter_wall_ns = now_ns() - enter_wall_start;
      const uint64_t end = thread_cpu_ns();
      if (enter_cpu_start && end >= enter_cpu_start)
        timing->enter_cpu_ns = end - enter_cpu_start;
      if (usage_valid && getrusage(RUSAGE_THREAD, &usage_after) == 0) {
        timing->voluntary_switches = static_cast<uint64_t>(
            std::max<long>(0, usage_after.ru_nvcsw - usage_before.ru_nvcsw));
        timing->involuntary_switches = static_cast<uint64_t>(
            std::max<long>(0, usage_after.ru_nivcsw - usage_before.ru_nivcsw));
        timing->output_blocks = static_cast<uint64_t>(
            std::max<long>(0, usage_after.ru_oublock - usage_before.ru_oublock));
      }
    }
    stream_inflight_ += accepted;
    return accepted;
  }

  bool waitAsync() {
    if (fd_ < 0 || !stream_inflight_) return false;
    int result;
    do {
      result = static_cast<int>(syscall(__NR_io_uring_enter, fd_, 0, 1,
          IORING_ENTER_GETEVENTS, nullptr, 0));
    } while (result < 0 && errno == EINTR);
    return result >= 0;
  }

  std::vector<Completion> reapAsync() {
    std::vector<Completion> ready;
    if (fd_ < 0) return ready;
    unsigned head = __atomic_load_n(cq_head_, __ATOMIC_RELAXED);
    const unsigned tail = __atomic_load_n(cq_tail_, __ATOMIC_ACQUIRE);
    ready.reserve(tail - head);
    while (head != tail) {
      const auto& cqe = cqes_[head & *cq_mask_];
      ready.push_back(Completion{cqe.user_data, cqe.res});
      ++head;
    }
    __atomic_store_n(cq_head_, head, __ATOMIC_RELEASE);
    stream_inflight_ -= std::min(stream_inflight_, ready.size());
    return ready;
  }

 private:
  template <typename T>
  static T* pointer(void* base, uint32_t offset) {
    return reinterpret_cast<T*>(static_cast<uint8_t*>(base) + offset);
  }

  bool sameBuffers(const std::vector<struct iovec>& buffers) const {
    if (buffers.size() != registered_buffers_.size())
      return false;
    for (size_t index = 0; index < buffers.size(); ++index)
      if (buffers[index].iov_base != registered_buffers_[index].iov_base ||
          buffers[index].iov_len != registered_buffers_[index].iov_len)
        return false;
    return true;
  }

  void unregisterFiles() {
    if (fd_ >= 0 && !registered_files_.empty())
      (void)syscall(__NR_io_uring_register, fd_,
                    IORING_UNREGISTER_FILES, nullptr, 0);
    registered_files_.clear();
  }

  void close_ring() {
    unregisterBuffers();
    unregisterFiles();
    if (sqes_ != MAP_FAILED)
      munmap(sqes_, sqes_size_);
    if (cq_ptr_ != MAP_FAILED && cq_ptr_ != sq_ptr_)
      munmap(cq_ptr_, cq_size_);
    if (sq_ptr_ != MAP_FAILED)
      munmap(sq_ptr_, sq_size_);
    if (fd_ >= 0)
      close(fd_);
    fd_ = -1;
    sq_ptr_ = cq_ptr_ = sqes_ = MAP_FAILED;
  }

  unsigned capacity_;
  int fd_;
  void* sq_ptr_;
  void* cq_ptr_;
  void* sqes_;
  size_t sq_size_;
  size_t cq_size_;
  size_t sqes_size_;
  unsigned* sq_head_;
  unsigned* sq_tail_;
  unsigned* sq_mask_;
  unsigned* sq_entries_;
  unsigned* sq_array_;
  unsigned* cq_head_;
  unsigned* cq_tail_;
  unsigned* cq_mask_;
  struct io_uring_cqe* cqes_;
  std::vector<int> registered_files_;
  std::vector<struct iovec> registered_buffers_;
  size_t stream_inflight_ = 0;
};
#endif

}
#endif

