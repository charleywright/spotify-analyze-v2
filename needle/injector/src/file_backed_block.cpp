#include "file_backed_block.hpp"
#include <cstring>
#include <fmt/format.h>

#ifdef _WIN32

// Windows code is completely untested and written using the MSDN documentation
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <intsafe.h>

std::string last_error()
{
  DWORD code = GetLastError();
  LPTSTR message = nullptr;
  DWORD message_len = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr, code, 0, reinterpret_cast<LPTSTR>(&message), 0,
                                     nullptr);
  if (message_len == 0)
  {
    return fmt::format("Failed to get an error message. Actual error code: {}\n", code);
  }
  std::string message_str(message, message_len);
  LocalFree(message);
  return message_str;
}

#else

#include <sys/mman.h>
#include <fcntl.h>
#include <cerrno>
#include <unistd.h>
#include <sys/stat.h>

#endif

file_backed_block::file_backed_block(const std::filesystem::path &file) : file_backed_block(file, 0, 0)
{

}

file_backed_block::file_backed_block(const std::filesystem::path &file_path, std::uint64_t offset, std::uint64_t size) : path(file_path)
{
#ifdef _WIN32
  HANDLE file = CreateFile(file_path.string().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, nullptr);
  if (file == INVALID_HANDLE_VALUE)
  {
    this->error_string = last_error();
    return;
  }
  this->mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (this->mapping == nullptr)
  {
    CloseHandle(file);
    this->error_string = last_error();
    return;
  }
  SYSTEM_INFO system_info{0};
  GetSystemInfo(&system_info);
  std::uint64_t aligned_offset = ((offset / system_info.dwAllocationGranularity) * system_info.dwAllocationGranularity);
  std::uint64_t offset_delta = offset - aligned_offset;
  std::uint64_t aligned_size = ((size + offset_delta + system_info.dwPageSize - 1) / system_info.dwPageSize) * system_info.dwPageSize;
  DWORD low_order_offset = LODWORD(aligned_offset);
  DWORD high_order_offset = HIDWORD(aligned_offset);
  this->view = MapViewOfFile(this->mapping, FILE_MAP_READ, high_order_offset, low_order_offset, aligned_size);
  CloseHandle(file);
  if (this->view == nullptr)
  {
    CloseHandle(this->mapping);
    this->error_string = last_error();
    return;
  }
#else
  int fd = open(file_path.string().c_str(), O_RDONLY);
  if (fd == -1)
  {
    this->error_string = fmt::format("Failed to open file {}: {}", file_path.string(), strerror(errno));
    return;
  }
  if (size == 0)
  {
    struct stat statbuf{0};
    if (fstat(fd, &statbuf) == -1)
    {
      this->error_string = fmt::format("Failed to stat file {}: {}", file_path.string(), strerror(errno));
      return;
    }
    size = statbuf.st_size;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  std::uint64_t aligned_offset = ((offset / page_size) * page_size);
  std::uint64_t offset_delta = offset - aligned_offset;
  std::uint64_t aligned_size = ((size + offset_delta + page_size - 1) / page_size) * page_size;

  this->view = mmap(nullptr, aligned_size, PROT_READ, MAP_PRIVATE, fd, static_cast<off_t>(aligned_offset));
  close(fd);
  if (this->view == MAP_FAILED)
  {
    this->error_string = fmt::format("Failed to map file {}: {}", file_path.string(), strerror(errno));
    return;
  }
#endif
  this->block_size = size;
  this->block_base = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(this->view) + offset_delta);
  this->block_cursor = this->block_base;
}

file_backed_block::~file_backed_block()
{
#ifdef _WIN32
  if (this->view != nullptr)
  {
    UnmapViewOfFile(this->view);
    this->view = nullptr;
  }
  if (this->mapping != nullptr)
  {
    CloseHandle(this->mapping);
    this->mapping = nullptr;
  }
#else
  if (this->view != nullptr)
  {
    munmap(this->view, this->block_size);
    this->view = nullptr;
  }
#endif
}

bool file_backed_block::error() const
{
  return !this->error_string.empty();
}

std::string file_backed_block::error_str() const
{
  return this->error_string;
}

std::uint64_t file_backed_block::size() const
{
  return this->block_size;
}

void *file_backed_block::base_ptr()
{
  return this->block_base;
}

void *file_backed_block::pos_ptr()
{
  return this->block_cursor;
}

std::uint64_t file_backed_block::pos() const
{
  return reinterpret_cast<std::uintptr_t>(this->block_cursor) - reinterpret_cast<std::uintptr_t>(this->block_base);
}

void file_backed_block::seek(std::uint64_t pos)
{
  this->block_cursor = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(this->block_base) + pos);
}

void file_backed_block::read(void *buffer, std::uint64_t size)
{
  std::memcpy(buffer, this->block_cursor, size);
  this->block_cursor = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(this->block_cursor) + size);
}
