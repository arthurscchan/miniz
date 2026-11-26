#include <stdio.h>
#include <limits.h>
#include "miniz.h"

static const mz_uint files_count = 5;
static const mz_uint max_file_size = 1024 * 1024;
static const char *zip_file_name = "/tmp/miniz-fuzzer-test.zip";

/* Read 32-bit integer from the fuzzer input with range [0, max] */
static mz_uint read_uint32(const mz_uint8 **data, size_t *size, mz_uint max)
{
    mz_uint value = 0;

    if (*size >= sizeof(mz_uint))
    {
        memcpy(&value, *data, sizeof(mz_uint));
        *data += sizeof(mz_uint);
        *size -= sizeof(mz_uint);
        value = MZ_MIN(max == UINT_MAX ? value : value % (max + 1), *size);
    }

    return value;
}

/* Read random-length null terminated string from the fuzzer input */
static mz_bool read_string(const mz_uint8 **data, size_t *size, char *destination, mz_uint max_len)
{
    mz_uint filename_len = read_uint32(data, size, max_len - 1);
    memcpy(destination, *data, filename_len);
    destination[filename_len] = 0;
    *data += filename_len;
    *size -= filename_len;
    return filename_len > 0;
}

/* Get random-length buffer from the fuzzer input */
static mz_bool read_buffer(const mz_uint8 **data, size_t *size, const mz_uint8 **destination, mz_uint *len)
{
    *len = read_uint32(data, size, max_file_size);
    *destination = *data;
    *data += *len;
    *size -= *len;
    return *len > 0;
}

/* Extraction size bound: the archive controls the declared uncompressed size,
   so a crafted entry could otherwise make mz_zip_extract_archive_file_to_heap
   allocate (or abort) with an attacker-chosen multi-gigabyte size and kill the
   coverage/fuzzing run. Bound the extraction like a defensive consumer. */
static const mz_uint64 max_extract_size = 8 * 1024 * 1024;

static mz_bool entry_size_is_extractable(const char *archive_name, const char *file_name)
{
    mz_zip_archive reader;
    mz_zip_archive_file_stat stat;
    mz_bool ok = MZ_FALSE;
    int index;

    MZ_CLEAR_OBJ(reader);
    if (!mz_zip_reader_init_file(&reader, archive_name, 0))
        return MZ_FALSE;

    index = mz_zip_reader_locate_file(&reader, file_name, NULL, 0);
    if (index >= 0 && mz_zip_reader_file_stat(&reader, (mz_uint)index, &stat))
        ok = stat.m_uncomp_size <= max_extract_size;

    mz_zip_reader_end(&reader);
    return ok;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mz_uint i;
    char archive_file_name[FILENAME_MAX];
    const mz_uint8 *file_data;
    mz_uint file_length, flags;
    size_t extracted_size;
    mz_uint8 *extracted_data;
    const char *comment = mz_version();

    /* Remove the temporary file for better reproducibility */
    remove(zip_file_name);

    for (i = 0; i < files_count; ++i)
    {
        /* Fill archive file name */
        if (!read_string(&data, &size, archive_file_name, sizeof(archive_file_name)))
        {
            break;
        }

        /* Prepare file's content */
        if (!read_buffer(&data, &size, &file_data, &file_length))
        {
            break;
        }

        /* Prepare flags for adding file */
        flags = read_uint32(&data, &size, UINT_MAX);

        mz_zip_add_mem_to_archive_file_in_place(zip_file_name, archive_file_name, file_data, file_length, comment,
                                                (mz_uint16)strlen(comment), flags);

        /* Prepare flags for extracting file */
        flags = read_uint32(&data, &size, UINT_MAX);

        /* Bound the extraction to the entry's declared (attacker-controlled)
           uncompressed size so a crafted archive cannot make the extract API
           allocate an attacker-chosen multi-gigabyte buffer and kill the run. */
        if (!entry_size_is_extractable(zip_file_name, archive_file_name))
            continue;

        extracted_data = mz_zip_extract_archive_file_to_heap(zip_file_name, archive_file_name, &extracted_size, flags);
        free(extracted_data);
    }

    remove(zip_file_name);
    return 0;
}
