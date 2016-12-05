/* Copyright (c) 2016 by the author(s)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * ============================================================================
 *
 * Author(s):
 *   Stefan Wallentowitz <stefan@wallentowitz.de>
 */

#include "osd-private.h"
#include <libglip.h>

#include <gelf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

/* global defines */
#define MAM_HEADER_0_WRITE           (1 << 15)
#define MAM_HEADER_0_CHUNKED         (1 << 14)
#define MAM_HEADER_0_SYNC            (1 << 13)
#define MAM_HEADER_0_SIZE__MASK  0xFFF

/**
 * Maximum size of a bulk transfer in bytes
 * This size is defined by the hardware specification/implementation.
 */
static const size_t BULK_MAX = 0x1f00;


static void memory_read_cb(struct osd_context *ctx, void* arg,
                           uint16_t* packet) {
    size_t numwords = packet[0] - 2;
    dbg(ctx, "Received %zu words from MAM", numwords);

    pthread_mutex_lock(&ctx->mem_access.lock);

    for (size_t i = 0; i < numwords; i++) {
        size_t idx = (ctx->mem_access.count + i)*2;
        ctx->mem_access.data[idx] = packet[3+i] & 0xff;
        ctx->mem_access.data[idx+1] = packet[3+i] >> 8;
    }

    ctx->mem_access.count += numwords;

    if (ctx->mem_access.count >= ctx->mem_access.size/2) {
        ctx->mem_access.complete = 1;
        pthread_cond_signal(&ctx->mem_access.cond_complete);
    }

    pthread_mutex_unlock(&ctx->mem_access.lock);
}

/**
 * Write a block of data to a memory through the MAM
 *
 * Only data up to BULK_MAX bytes can be written.
 *
 * The MAM and this function have two modes of operation: asynchronous and
 * synchronous transfers. By default asynchronous transfers are used. In this
 * mode, the transfer is only submitted to the hardware, but the software does
 * not wait for the request to complete.
 * In synchronous mode, the hardware acknowledges writes and this function waits
 * for this acknowledgement to arrive before returning to the caller.
 *
 * @param ctx the library context
 * @param modid the module ID of the MAM
 * @param addr the start address of the memory read
 * @param data the read data
 * @param size number of bytes to write; must be below BULK_MAX
 * @param sync request a synchronous write
 *
 * @return 0 on success
 * @return any other value indicates an error
 */
static int memory_write_bulk(struct osd_context *ctx, uint16_t modid,
                             uint64_t addr, uint8_t* data, size_t size,
                             int sync) {

    int rv = OSD_SUCCESS;

    if (size > BULK_MAX) {
        err(ctx, "size %zu exceeds maximum bulk size of %zu bytes.", size,
            BULK_MAX);
        return -1;
    }

    uint16_t modaddr = osd_modid2addr(ctx, modid);

    uint16_t psize = osd_get_max_pkt_len(ctx);
    uint16_t wordsperpacket = psize - 2;


    // reused buffer for all packets to be sent; allocated to the maxumum
    // size allowed by OSD
    uint16_t *packet = malloc((psize + 1) * sizeof(uint16_t));

    struct osd_memory_descriptor *mem;
    mem = ctx->system_info->modules[modid].descriptor.memory;

    // calculate the size of the bulk transfer in words (according to the
    // memory's word width) and NoC flits
    size_t numwords = size/(mem->data_width >> 3);
    size_t numflits = size/sizeof(uint16_t);

    // nothing to do
    if (numflits == 0) {
        rv = 0;
        goto free_return;
    }

    size_t hlen = 1; // control word
    hlen += ((mem->addr_width + 15) >> 4);
    uint16_t *header = &packet[3];


    // build the MAM header
    header[0] = MAM_HEADER_0_CHUNKED | MAM_HEADER_0_WRITE;
    if (sync) {
        header[0] |= MAM_HEADER_0_SYNC;
    }
    header[0] |= numwords & MAM_HEADER_0_SIZE__MASK;

    header[1] = addr & 0xffff;
    if (mem->addr_width > 16)
        header[2] = (addr >> 16) & 0xffff;
    if (mem->addr_width > 32)
        header[3] = (addr >> 32) & 0xffff;
    if (mem->addr_width > 48)
        header[4] = (addr >> 48) & 0xffff;


    // register receive listener for synchronous transfers
    if (sync) {
        pthread_mutex_lock(&ctx->mem_access.lock);
        // another thread has not yet reset the complete signal.
        // this indicates an error on the calling side
        assert(ctx->mem_access.complete == 0);

        ctx->mem_access.size = 0;
        ctx->mem_access.data = 0;
        ctx->mem_access.count = 0;
        ctx->mem_access.complete = 0;
        osd_module_register_handler(ctx, modid, OSD_EVENT_PACKET, 0,
                                    memory_read_cb);
        pthread_mutex_unlock(&ctx->mem_access.lock);
    }

    // the module address is always the same
    packet[1] = modaddr;

    // the first packet is only header
    packet[0] = hlen + 2;
    packet[2] = 1 << 14;
    osd_send_packet(ctx, packet);

    int curword = 0;

    // all completely filled packets
    for (size_t i = 0; i < numflits; i++) {
        packet[3+curword] = (data[i*2] << 8) | data[i*2+1];
        curword++;

        if (curword == wordsperpacket) {
            packet[0] = psize;
            osd_send_packet(ctx, packet);
            curword = 0;
        }
    }

    // the last packet with the remaining data words
    if (curword != 0) {
        packet[0] = curword + 2;
        osd_send_packet(ctx, packet);
    }

    // in synchronous mode, wait for the acknowledgement packet to arrive
    if (sync) {
        pthread_mutex_lock(&ctx->mem_access.lock);
        while (ctx->mem_access.complete != 1) {
            pthread_cond_wait(&ctx->mem_access.cond_complete,
                              &ctx->mem_access.lock);
        }
        ctx->mem_access.complete = 0;
        osd_module_unregister_handler(ctx, modid, OSD_EVENT_PACKET);
        pthread_mutex_unlock(&ctx->mem_access.lock);
    }

free_return:
    free(packet);

    return rv;
}

/**
 * Write a single word to memory
 *
 * @param ctx the library context
 * @param modid the module ID of the MAM
 * @param addr the start address of the memory read
 * @param data the read data
 * @param size number of bytes to write; must be below BULK_MAX
 *
 * @return 0 on success
 * @return any other value indicates an error
 */
static int memory_write_single(struct osd_context *ctx, uint16_t modid,
                               uint64_t addr, uint8_t* data, size_t size) {
    uint16_t modaddr = osd_modid2addr(ctx, modid);

    uint16_t psize = osd_get_max_pkt_len(ctx);

    uint16_t *packet = malloc((psize+1)*2);

    struct osd_memory_descriptor *mem;
    mem = ctx->system_info->modules[modid].descriptor.memory;

    size_t hlen = 1; // control word
    hlen += ((mem->addr_width + 15) >> 4);
    uint16_t *header = &packet[3];

    uint8_t strobe = 0;
    size_t blocksize = mem->data_width >> 3;
    uint8_t baddr = addr % blocksize;

    for (size_t i = 0; i < blocksize; i++) {
        if ((i >= baddr) && (i < baddr + size)) {
            strobe |= 1 << i;
        }
    }

    addr = addr - (addr % blocksize);

    header[0] = 0x8000 | strobe;
    header[1] = addr & 0xffff;
    if (mem->addr_width > 16)
        header[2] = (addr >> 16) & 0xffff;
    if (mem->addr_width > 32)
        header[3] = (addr >> 32) & 0xffff;
    if (mem->addr_width > 48)
        header[4] = (addr >> 48) & 0xffff;

    // Static for packets
    packet[0] = hlen + 2 + blocksize/2;
    packet[1] = modaddr;
    packet[2] = 1 << 14;

    uint8_t *block = calloc(1, blocksize);
    memcpy(&block[baddr], data, size);

    for (size_t i = 0; i < blocksize/2; i++) {
        packet[i+3+hlen] = (block[i*2] << 8) | block[i*2+1];
    }

    osd_send_packet(ctx, packet);

    return 0;
}

static int memory_read_bulk(struct osd_context *ctx, uint16_t modid,
                            uint64_t addr,
                            uint8_t* data, size_t size) {
    uint16_t modaddr = osd_modid2addr(ctx, modid);
    uint16_t psize = osd_get_max_pkt_len(ctx);

    uint16_t *packet = malloc((psize+1)*2);

    struct osd_memory_descriptor *mem;
    mem = ctx->system_info->modules[modid].descriptor.memory;

    size_t numwords = size/(mem->data_width >> 3);

    size_t hlen = 1; // control word
    hlen += ((mem->addr_width + 15) >> 4);
    uint16_t *header = &packet[3];

    header[0] = 0x4000 | numwords;
    header[1] = addr & 0xffff;
    if (mem->addr_width > 16)
        header[2] = (addr >> 16) & 0xffff;
    if (mem->addr_width > 32)
        header[3] = (addr >> 32) & 0xffff;
    if (mem->addr_width > 48)
        header[4] = (addr >> 48) & 0xffff;

    osd_module_claim(ctx, modid);
    osd_module_register_handler(ctx, modid, OSD_EVENT_PACKET, 0, memory_read_cb);

    // Static for packets
    packet[0] = hlen + 2;
    packet[1] = modaddr;
    packet[2] = 1 << 14;

    pthread_mutex_lock(&ctx->mem_access.lock);
    ctx->mem_access.size = size;
    ctx->mem_access.data = data;
    ctx->mem_access.count = 0;
    ctx->mem_access.complete = 0;

    osd_send_packet(ctx, packet);

    pthread_cond_wait(&ctx->mem_access.cond_complete,
                      &ctx->mem_access.lock);
    uint8_t buf = 0;
    for (size_t i = 0; i < (size/2); i++) {
        buf = data[2*i];
        data[2*i] = data[2*i+1];
        data[2*i+1] = buf;
    }


    pthread_mutex_unlock(&ctx->mem_access.lock);

    return 0;
}

static void calculate_parts(uint64_t addr, size_t size, size_t blocksize,
                            size_t *prolog, size_t *bulk, size_t *epilog) {
    if (size < blocksize) {
        *prolog = size;
        *epilog = 0;
        *bulk = 0;
    } else {
        *prolog = (blocksize - addr) % blocksize;
        *epilog = ((addr + size) % blocksize);
        *bulk = size - *prolog - *epilog;
    }
}

/**
 * Write data to a memory attached to a MAM
 *
 * @param ctx the library context
 * @param modid the module ID of the MAM
 * @param addr the start address of the memory write
 * @param data the read to write
 * @param size number of bytes to read
 * @return 0 on success
 * @return any other value indicates an error
 */
OSD_EXPORT
int osd_memory_write(struct osd_context *ctx, uint16_t modid, uint64_t addr,
                     uint8_t* data, size_t size) {

    osd_module_claim(ctx, modid);

    struct osd_memory_descriptor *mem;
    mem = ctx->system_info->modules[modid].descriptor.memory;

    size_t blocksize = mem->data_width >> 3;

    size_t prolog, bulk, epilog;
    calculate_parts(addr, size, blocksize, &prolog, &bulk, &epilog);

    if (prolog) {
        dbg(ctx, "Writing ELF prolog");
        // XXX: this should be sync as well (if no bulk/epilog exists)
        memory_write_single(ctx, modid, addr, data, prolog);
    }

    if (bulk) {
        dbg(ctx, "Writing bulk part of ELF file");
        for (size_t i = 0; i < size; i += BULK_MAX) {
            size_t s = BULK_MAX;

            if ((i+s) > bulk) {
                s = bulk - i;
            }

            // issue a synchronous transfer if this is the last transfer of the
            // bulk write
            int is_last_pkg = ((i+s) == bulk);

            memory_write_bulk(ctx, modid, addr+prolog+i, &data[prolog+i], s,
                              is_last_pkg);
        }
    }

    if (epilog) {
        dbg(ctx, "writing epilog of ELF file");
        // XXX: this must be sync as well
        memory_write_single(ctx, modid, addr+prolog+bulk, &data[prolog+bulk], epilog);
    }

    // XXX: function does not yet exist
    //osd_module_unclaim(ctx, modid);

    return 0;
}

/**
 * Read the contents of a memory though a MAM module
 *
 * @param ctx the library context
 * @param modid the module ID of the MAM
 * @param addr the start address of the memory read
 * @param[out] data the read data
 * @param size number of bytes to read
 * @return 0 on success
 * @return any other value indicates an error
 */
OSD_EXPORT
int osd_memory_read(struct osd_context *ctx, uint16_t modid, uint64_t addr,
                     uint8_t* data, size_t size) {
    struct osd_memory_descriptor *mem;
    mem = ctx->system_info->modules[modid].descriptor.memory;

    size_t blocksize = mem->data_width >> 3;

    size_t prolog, bulk, epilog;
    calculate_parts(addr, size, blocksize, &prolog, &bulk, &epilog);

    if (prolog) {
        uint8_t *tmp = malloc(blocksize);
        memory_read_bulk(ctx, modid, addr - blocksize + prolog, tmp, blocksize);
        memcpy(data, &tmp[blocksize-prolog], prolog);
        free(tmp);
    }

    if (bulk) {
        for (size_t i = 0; i < size; i += BULK_MAX) {
            size_t s = BULK_MAX;

            if ((i+s) > size) s = bulk - i;

            memory_read_bulk(ctx, modid, addr + prolog + i, &data[prolog+i], s);
        }
    }

    if (epilog) {
        uint8_t *tmp = malloc(blocksize);
        memory_read_bulk(ctx, modid, addr + prolog + bulk, tmp, blocksize);
        memcpy(&data[prolog+bulk], tmp, epilog);
        free(tmp);
    }

    return 0;
}

/**
 * Load an ELF file into the system through a MAM module
 *
 * @param ctx the library context
 * @param modid the ID of the MAM module to load
 * @param filename path to the ELF file to load
 * @param verify verify the memory writing by reading it back and comparing it?
 * @return 0 on success
 * @return any other value indicates an error
 */
OSD_EXPORT
int osd_memory_loadelf(struct osd_context *ctx, uint16_t modid,
                       char *filename, int verify) {
    int fd;
    Elf *elf_object;
    size_t num;
    int rv = OSD_SUCCESS;

    fd = open(filename, O_RDONLY , 0);
    if (fd < 0) {
        err(ctx, "Cannot open file: %d. %s", errno, strerror(errno));
        return -1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        rv = OSD_E_GENERIC;
        goto return_file;
    }

    elf_object = elf_begin(fd , ELF_C_READ , NULL);
    if (elf_object == NULL) {
        err(ctx, "%s", elf_errmsg(-1));
        rv = OSD_E_GENERIC;
        goto return_file;
    }

    // Load program headers
    if (elf_getphdrnum(elf_object, &num)) {
        rv = OSD_E_GENERIC;
        goto return_elf;
    }

    for (size_t i = 0; i < num; i++) {
        info(ctx, "Load program header %zu", i);
        GElf_Phdr phdr;
        Elf_Data *data;
        if (gelf_getphdr(elf_object, i, &phdr) != &phdr) {
            rv = OSD_E_GENERIC;
            goto return_elf;
        }

        data = elf_getdata_rawchunk(elf_object, phdr.p_offset, phdr.p_filesz,
                                    ELF_T_BYTE);
        if (data) {
            osd_memory_write(ctx, modid, phdr.p_paddr, data->d_buf,
                             data->d_size);
        }

        Elf32_Word init_with_zero = phdr.p_memsz - phdr.p_filesz;
        if (init_with_zero > 0) {
            void *zeroes = calloc(1, phdr.p_memsz - phdr.p_filesz);
            osd_memory_write(ctx, modid, phdr.p_paddr + phdr.p_filesz,
                             zeroes, init_with_zero);
            free(zeroes);
        }
    }

    if (!verify) {
        goto return_elf;
    }

    for (size_t i = 0; i < num; i++) {
        info(ctx, "Verify program header %zu\n", i);
        GElf_Phdr phdr;
        Elf_Data *data;
        if (gelf_getphdr(elf_object, i, &phdr) != &phdr) {
            rv = OSD_E_GENERIC;
            goto return_elf;
        }

        data = elf_getdata_rawchunk(elf_object, phdr.p_offset, phdr.p_filesz,
                                    ELF_T_BYTE);
        uint8_t *elf_data = data->d_buf;

        uint8_t *memory_data = malloc(data->d_size);
        osd_memory_read(ctx, modid, phdr.p_paddr, memory_data, data->d_size);

        for (size_t b = 0; b < data->d_size; b++) {
            if (memory_data[b] != elf_data[b]) {
                err(ctx, "Memory mismatch at byte 0x%zx. expected: %02x, "
                    "found: %02x", b, elf_data[b], memory_data[b]);
                rv = OSD_E_GENERIC;
                goto return_elf;
            }
        }

        free(memory_data);
    }

return_elf:
    elf_end(elf_object);

return_file:
    close(fd);
    return rv;
}
