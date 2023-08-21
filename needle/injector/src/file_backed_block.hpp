#pragma once

#include <filesystem>
#include <fstream>
#include <cstdint>

/*
 * An abstraction over mmap and MapViewOfFile to read binary files
 */
class file_backed_block
{
public:
    explicit file_backed_block(const std::filesystem::path &file);
    explicit file_backed_block(const std::filesystem::path &file, std::uint64_t offset, std::uint64_t size);
    ~file_backed_block();

    /*
     * Get the size of the block
     */
    std::uint64_t size() const;

    /*
     * Get a pointer to the base of the block
     */
    void *base_ptr();

    /*
     * Get a pointer to the current position of the cursor
     */
    void *pos_ptr();

    /*
     * Get the current position of the cursor
     */
    std::uint64_t pos() const;

    /*
     * Seek to a position in the block
     */
    void seek(std::uint64_t pos);

    /*
     * Read `size` bytes from the cursor into `buffer`
     */
    void read(void *buffer, std::uint64_t size);

private:
    const std::filesystem::path &path;

    // Windows requires a mapping and a view. On Linux we just use the view
    void *mapping = nullptr;
    void *view = nullptr;

    std::uint64_t block_size = 0;
    void *cursor = nullptr;
};
