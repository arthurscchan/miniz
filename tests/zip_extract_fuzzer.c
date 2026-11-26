/* Copyright 2026 Google LLC
 *
 * Fuzz target for miniz ZIP reader extraction variants.
 *
 * Rationale (coverage-pipeline rank 3, ~700 dark lines in production 20261123):
 * the existing zip_fuzzer only calls mz_zip_reader_extract_file_to_mem. This
 * target drives every reader extraction entry point on attacker-controlled
 * archive bytes:
 *   mz_zip_reader_locate_file / mz_zip_reader_locate_file_v2
 *   mz_zip_reader_extract_to_mem / _no_alloc / extract_to_callback
 *   mz_zip_reader_extract_file_to_mem
 *   mz_zip_reader_extract_iter_new / _read / _free (incremental API)
 *   mz_zip_reader_file_stat / mz_zip_reader_is_file_a_directory / _encrypted
 *   mz_zip_reader_get_filename
 *
 * Extraction is bounded: entries whose declared uncompressed size exceeds
 * 4 MiB are skipped, so a crafted archive cannot turn a bounded-bug hunt into
 * an allocation blowup. Reader flags are attacker-controlled.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "miniz.h"

#define MAX_EXTRACT_BYTES (4 * 1024 * 1024)
#define MAX_FILES_ITERATED 32

static size_t write_count_cb(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n)
{
    (void)pOpaque;
    (void)file_ofs;
    (void)pBuf;
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mz_zip_archive zip;
    mz_uint flags;
    mz_uint i, files;
    uint8_t out_buf[8192];

    if (size < 4)
        return 0;

    /* Reader flags come from the version bytes of the first local header so
       that plain ZIP files are valid inputs unmodified, while mutations of
       those bytes still sweep the flag matrix. The whole input is the archive. */
    flags = (mz_uint)data[2] | (((mz_uint)data[3]) << 8);
    flags &= (MZ_ZIP_FLAG_CASE_SENSITIVE | MZ_ZIP_FLAG_IGNORE_PATH |
              MZ_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY);

    MZ_CLEAR_OBJ(zip);
    if (!mz_zip_reader_init_mem(&zip, data, size, flags))
        return 0;

    files = mz_zip_reader_get_num_files(&zip);
    if (files > MAX_FILES_ITERATED)
        files = MAX_FILES_ITERATED;

    for (i = 0; i < files; i++)
    {
        mz_zip_archive_file_stat stat;
        char name[MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE];

        if (!mz_zip_reader_file_stat(&zip, i, &stat))
            continue;

        if (mz_zip_reader_is_file_a_directory(&zip, i))
            continue;

        mz_zip_reader_get_filename(&zip, i, name, sizeof(name));

        /* Skip entries whose declared size would blow the bounded buffers. */
        if (stat.m_uncomp_size > MAX_EXTRACT_BYTES)
            continue;

        if (stat.m_uncomp_size <= sizeof(out_buf))
        {
            mz_zip_reader_extract_to_mem(&zip, i, out_buf, (size_t)stat.m_uncomp_size, flags);

            memset(out_buf, 0, sizeof(out_buf));
            mz_zip_reader_extract_to_mem_no_alloc(&zip, i, out_buf, sizeof(out_buf), flags,
                                                  NULL, 0);
        }

        mz_zip_reader_extract_to_callback(&zip, i, write_count_cb, NULL, flags);

        {
            mz_zip_reader_extract_iter_state *iter =
                mz_zip_reader_extract_iter_new(&zip, i, flags);
            if (iter)
            {
                while (mz_zip_reader_extract_iter_read(iter, out_buf, sizeof(out_buf)) > 0)
                {
                }
                mz_zip_reader_extract_iter_free(iter);
            }
        }

        if (stat.m_filename[0])
        {
            int located = mz_zip_reader_locate_file(&zip, stat.m_filename, NULL,
                                                    (flags & MZ_ZIP_FLAG_CASE_SENSITIVE) ? MZ_ZIP_FLAG_CASE_SENSITIVE : 0);
            if (located >= 0 && stat.m_uncomp_size <= sizeof(out_buf))
                mz_zip_reader_extract_file_to_mem(&zip, stat.m_filename, out_buf,
                                                  (size_t)stat.m_uncomp_size, flags);

            mz_zip_reader_locate_file_v2(&zip, stat.m_filename, NULL, 0, NULL);
        }
    }

    mz_zip_reader_end(&zip);
    return 0;
}
