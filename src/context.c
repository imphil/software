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

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>

static
int osd_new_standalone(struct osd_context_standalone **ctx,
                       struct osd_mode_functions *fnc,
                       size_t num_mode_options,
                       struct osd_mode_option *options);

static
int osd_new_daemon(struct osd_context_daemon **ctx,
                   struct osd_mode_functions *fnc,
                   size_t num_mode_options,
                   struct osd_mode_option *options);



/**
 * Set a caller context pointer
 *
 * In some cases OSD executes callback functions. These functions always
 * provide the OSD context object of type struct osd_context. To make it
 * possible to associate the OSD context with the right context of the calling
 * application register the context or <code>this</code> (in C++) pointer with
 * OSD and retrieve it inside the callback using osd_get_caller_ctx().
 *
 * OSD does not use this pointer in any way, you're free to set it to whatever
 * your application needs.
 *
 * @param ctx        the library context
 * @param caller_ctx the caller context pointer
 *
 * @see osd_get_caller_ctx()
 * @see osd_set_log_fn() for a code example using this functionality
 *
 * @ingroup utilities
 */
OSD_EXPORT
void osd_set_caller_ctx(struct osd_context *ctx, void *caller_ctx)
{
    ctx->caller_ctx = caller_ctx;
}



/**
 * Default logging function: log to STDERR
 *
 * @see osd_log()
 */
static void log_stderr(struct osd_context *ctx, int priority, const char *file,
                       int line, const char *fn, const char *format,
                       va_list args)
{
    fprintf(stderr, "osd: %s: ", fn);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}

/**
 * Get the log priority as integer for a priority name
 *
 * @param priority the priority name
 * @return the priority as integer
 */
static int log_priority(const char *priority)
{
    char *endptr;
    int prio;

    prio = strtol(priority, &endptr, 10);
    if (endptr[0] == '\0' || isspace(endptr[0]))
        return prio;
    if (strncmp(priority, "err", 3) == 0)
        return LOG_ERR;
    if (strncmp(priority, "info", 4) == 0)
        return LOG_INFO;
    if (strncmp(priority, "debug", 5) == 0)
        return LOG_DEBUG;
    return 0;
}

/**
 * Create new library context
 */
OSD_EXPORT
int osd_new(struct osd_context **ctx, enum osd_mode mode,
            size_t num_mode_options, struct osd_mode_option *options) {
    if ((mode != OSD_MODE_STANDALONE) &&
            (mode != OSD_MODE_DAEMON)) {
        return OSD_E_GENERIC;
    }

    struct osd_context *c = calloc(1, sizeof(struct osd_context));
    *ctx = c;

    // Activate for low level debugging
    //c->debug_packets = 1;

    /*
     * Setup the logging infrastructure
     */
    c->log_fn = log_stderr;
    c->log_priority = LOG_ERR;

    /* environment overwrites config */
    const char *env;
    env = getenv("OSD_LOG");
    if (env != NULL) {
        c->log_priority = log_priority(env);
    }
    dbg(c, "log_priority=%d\n", c->log_priority);

    if (mode == OSD_MODE_STANDALONE) {
        return osd_new_standalone(&c->ctx.standalone, &c->functions,
                                  num_mode_options, options);
    } else {
        return osd_new_daemon(&c->ctx.daemon, &c->functions,
                              num_mode_options, options);
    }

    return OSD_E_GENERIC;
}

static
int osd_new_standalone(struct osd_context_standalone **ctx,
                       struct osd_mode_functions *fnc,
                       size_t num_mode_options,
                       struct osd_mode_option *options) {
    struct osd_context_standalone *c = malloc(sizeof(struct osd_context_standalone));

    *ctx = c;

    struct glip_option *glip_options = calloc(num_mode_options, sizeof(struct glip_option));
    char *backend_name = 0;
    size_t num_glip_options = 0;

    for (size_t i = 0; i < num_mode_options; i++) {
        if (strcmp(options[i].name, "backend") == 0) {
            backend_name = options[i].value;
        } else if (strcmp(options[i].name, "backend_option") == 0) {
            char *name, *value;
            name = strtok(options[i].value, "=");
            value = strtok(NULL, "");
            glip_options[num_glip_options].name = name;
            glip_options[num_glip_options].value = value;
            num_glip_options++;
        }
    }

    fnc->connect = osd_connect_standalone;
    fnc->send = osd_send_packet_standalone;
    fnc->claim = claim_standalone;

    return glip_new(&c->glip_ctx, backend_name, glip_options, num_glip_options);
}

static
int osd_new_daemon(struct osd_context_daemon **ctx,
                   struct osd_mode_functions *fnc,
                   size_t num_mode_options,
                   struct osd_mode_option *options) {

    struct osd_context_daemon *c = malloc(sizeof(struct osd_context_daemon));

    *ctx = c;

    c->host = strdup("localhost");
    c->port = 7450;
    fnc->connect = osd_connect_daemon;
    fnc->send = osd_send_packet_daemon;
    fnc->claim = claim_daemon;

    return 0;
}
