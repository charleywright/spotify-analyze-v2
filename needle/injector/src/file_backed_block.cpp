#include "file_backed_block.hpp"
#include <cstring>

#ifdef _WIN32

// Windows code is completely untested and written using the MSDN documentation
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#else

#include <sys/mman.h>
#include <fcntl.h>
#include <cerrno>
#include <unistd.h>
#include <fmt/format.h>

#endif

file_backed_block::file_backed_block(const std::filesystem::path &file) : file_backed_block(file, 0, 0)
{

}

file_backed_block::file_backed_block(const std::filesystem::path &file, std::uint64_t offset, std::uint64_t size) : path(file)
{
#ifdef _WIN32
  HANDLE file = CreateFile(file.string().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  this->mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  DWORD high_order_offset = static_cast<DWORD>(offset >> 32);
  DWORD low_order_offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
  this->view = MapViewOfFile(this->mapping, FILE_MAP_READ, high_order_offset, low_order_offset, size);
  CloseHandle(file);
#else
  int fd = open(file.string().c_str(), O_RDONLY);
  if (fd == -1)
  {
    throw std::runtime_error(fmt::format("Failed to open file {}: {}", file.string(), strerror(errno)));
  }
  this->view = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, static_cast<off_t>(offset));
  close(fd);
#endif
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

std::uint64_t file_backed_block::size() const
{
  return this->block_size;
}

void *file_backed_block::base_ptr()
{
  return this->view;
}

void *file_backed_block::pos_ptr()
{
  return this->cursor;
}

std::uint64_t file_backed_block::pos() const
{
  return reinterpret_cast<std::uintptr_t>(this->cursor) - reinterpret_cast<std::uintptr_t>(this->view);
}

void file_backed_block::seek(std::uint64_t pos)
{
  this->cursor = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(this->view) + pos);
}

void file_backed_block::read(void *buffer, std::uint64_t size)
{
  std::memcpy(buffer, this->cursor, size);
  this->cursor = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(this->cursor) + size);
}
