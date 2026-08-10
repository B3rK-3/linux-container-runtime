/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define COUNT_LIMIT_MAX 1048576ULL
#define HOSTNAME_LIMIT 64U
#define CPU_PERIOD_MIN 1000ULL
#define CPU_PERIOD_MAX 1000000ULL
#define CPU_QUOTA_MIN 1000ULL

static bool parse_decimal_span(const char *text, size_t length, uint64_t *value)
{
    char buffer[32];
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || value == NULL || length == 0U ||
        length >= sizeof(buffer))
    {
        return false;
    }
    for (size_t i = 0; i < length; ++i)
    {
        if (!isdigit((unsigned char)text[i]))
        {
            return false;
        }
    }

    memcpy(buffer, text, length);
    buffer[length] = '\0';
    errno = 0;
    parsed = strtoull(buffer, &end, 10);
    if (errno == ERANGE || end == buffer || *end != '\0')
    {
        return false;
    }
    *value = (uint64_t)parsed;
    return true;
}

bool config_parse_bytes(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long amount;
    uint64_t multiplier = 1U;

    if (text == NULL || value == NULL || !isdigit((unsigned char)text[0]))
    {
        return false;
    }

    errno = 0;
    amount = strtoull(text, &end, 10);
    if (errno == ERANGE || end == text)
    {
        return false;
    }

    if (*end == '\0' || strcasecmp(end, "B") == 0)
    {
        multiplier = 1U;
    }
    else if (strcasecmp(end, "K") == 0 ||
             strcasecmp(end, "KB") == 0 ||
             strcasecmp(end, "KiB") == 0)
    {
        multiplier = 1024ULL;
    }
    else if (strcasecmp(end, "M") == 0 ||
             strcasecmp(end, "MB") == 0 ||
             strcasecmp(end, "MiB") == 0)
    {
        multiplier = 1024ULL * 1024ULL;
    }
    else if (strcasecmp(end, "G") == 0 ||
             strcasecmp(end, "GB") == 0 ||
             strcasecmp(end, "GiB") == 0)
    {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
    }
    else
    {
        return false;
    }

    if (amount == 0ULL || amount > UINT64_MAX / multiplier)
    {
        return false;
    }
    *value = (uint64_t)amount * multiplier;
    return true;
}

bool config_parse_cpu(const char *text, struct cpu_limit *value)
{
    const char *slash;
    uint64_t quota;
    uint64_t period;

    if (text == NULL || value == NULL)
    {
        return false;
    }
    slash = strchr(text, '/');
    if (slash == NULL || strchr(slash + 1, '/') != NULL)
    {
        return false;
    }
    if (!parse_decimal_span(text, (size_t)(slash - text), &quota) ||
        !parse_decimal_span(slash + 1, strlen(slash + 1), &period))
    {
        return false;
    }
    if (quota < CPU_QUOTA_MIN || period < CPU_PERIOD_MIN ||
        period > CPU_PERIOD_MAX)
    {
        return false;
    }
    value->quota = quota;
    value->period = period;
    return true;
}

bool config_parse_count(const char *text,
                        uint64_t minimum,
                        uint64_t maximum,
                        uint64_t *value)
{
    uint64_t parsed;

    if (text == NULL || value == NULL || minimum > maximum ||
        !parse_decimal_span(text, strlen(text), &parsed) || parsed < minimum ||
        parsed > maximum)
    {
        return false;
    }
    *value = parsed;
    return true;
}

bool config_valid_hostname(const char *hostname)
{
    size_t length;

    if (hostname == NULL)
    {
        return false;
    }
    length = strlen(hostname);
    if (length == 0U || length > HOSTNAME_LIMIT)
    {
        return false;
    }
    if (!isalnum((unsigned char)hostname[0]) ||
        !isalnum((unsigned char)hostname[length - 1U]))
    {
        return false;
    }
    for (size_t i = 0; i < length; ++i)
    {
        unsigned char c = (unsigned char)hostname[i];
        if (!isalnum(c) && c != '-' && c != '.')
        {
            return false;
        }
        if (i > 0U && hostname[i] == '.' && hostname[i - 1U] == '.')
        {
            return false;
        }
    }
    return true;
}

void config_init(struct container_config *config)
{
    memset(config, 0, sizeof(*config));
    config->memory_bytes = CONTAINED_DEFAULT_MEMORY;
    config->cpu.quota = CONTAINED_DEFAULT_CPU_QUOTA;
    config->cpu.period = CONTAINED_DEFAULT_CPU_PERIOD;
    config->pids = CONTAINED_DEFAULT_PIDS;
    config->nofile = CONTAINED_DEFAULT_NOFILE;
    config->cgroup_parent = CONTAINED_DEFAULT_CGROUP_PARENT;
}

void config_print_usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s --rootfs PATH [OPTIONS] -- COMMAND [ARG...]\n"
            "\n"
            "Required:\n"
            "  -r, --rootfs PATH          Root filesystem directory\n"
            "\n"
            "Resource limits:\n"
            "  -m, --memory BYTES         Memory maximum (default 256M)\n"
            "  -c, --cpu QUOTA/PERIOD     cgroup v2 cpu.max values\n"
            "                              (default 50000/100000)\n"
            "  -p, --pids COUNT           Process maximum (default 64)\n"
            "  -f, --nofile COUNT         Open-file limit (default 256)\n"
            "\n"
            "Isolation options:\n"
            "  -H, --hostname NAME        UTS hostname (generated by default)\n"
            "  -C, --cgroup-parent PATH   Delegated cgroup v2 directory\n"
            "                              (default /sys/fs/cgroup)\n"
            "      --writable-rootfs       Do not remount the rootfs read-only\n"
            "  -h, --help                  Show this help\n"
            "\n"
            "Byte suffixes K, M, G, KiB, MiB, and GiB use powers of 1024.\n",
            program);
}

enum config_parse_result config_parse(struct container_config *config,
                                      int argc,
                                      char **argv,
                                      FILE *errors)
{
    enum
    {
        OPT_WRITABLE_ROOTFS = 1000
    };
    static const struct option options[] = {
        {"rootfs", required_argument, NULL, 'r'},
        {"memory", required_argument, NULL, 'm'},
        {"cpu", required_argument, NULL, 'c'},
        {"pids", required_argument, NULL, 'p'},
        {"nofile", required_argument, NULL, 'f'},
        {"hostname", required_argument, NULL, 'H'},
        {"cgroup-parent", required_argument, NULL, 'C'},
        {"writable-rootfs", no_argument, NULL, OPT_WRITABLE_ROOTFS},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option;

    config_init(config);
    opterr = 0;
    while ((option = getopt_long(argc, argv, "+r:m:c:p:f:H:C:h", options,
                                 NULL)) != -1)
    {
        switch (option)
        {
        case 'r':
            config->rootfs = optarg;
            break;
        case 'm':
            if (!config_parse_bytes(optarg, &config->memory_bytes))
            {
                fprintf(errors, "contained: invalid memory limit '%s'\n", optarg);
                return CONFIG_PARSE_ERROR;
            }
            break;
        case 'c':
            if (!config_parse_cpu(optarg, &config->cpu))
            {
                fprintf(errors,
                        "contained: invalid CPU limit '%s' (expected QUOTA/PERIOD; "
                        "period 1000..1000000)\n",
                        optarg);
                return CONFIG_PARSE_ERROR;
            }
            break;
        case 'p':
            if (!config_parse_count(optarg, 1U, COUNT_LIMIT_MAX,
                                    &config->pids))
            {
                fprintf(errors, "contained: invalid PID limit '%s'\n", optarg);
                return CONFIG_PARSE_ERROR;
            }
            break;
        case 'f':
            if (!config_parse_count(optarg, 3U, COUNT_LIMIT_MAX,
                                    &config->nofile))
            {
                fprintf(errors,
                        "contained: invalid file-descriptor limit '%s'\n",
                        optarg);
                return CONFIG_PARSE_ERROR;
            }
            break;
        case 'H':
            if (!config_valid_hostname(optarg))
            {
                fprintf(errors, "contained: invalid hostname '%s'\n", optarg);
                return CONFIG_PARSE_ERROR;
            }
            config->hostname = optarg;
            break;
        case 'C':
            if (optarg[0] == '\0')
            {
                fprintf(errors, "contained: cgroup parent must not be empty\n");
                return CONFIG_PARSE_ERROR;
            }
            config->cgroup_parent = optarg;
            break;
        case OPT_WRITABLE_ROOTFS:
            config->writable_rootfs = true;
            break;
        case 'h':
            return CONFIG_PARSE_HELP;
        case '?':
        default:
            if (optopt != 0)
            {
                fprintf(errors, "contained: unknown or incomplete option '-%c'\n",
                        optopt);
            }
            else
            {
                fprintf(errors, "contained: unknown option\n");
            }
            return CONFIG_PARSE_ERROR;
        }
    }

    if (config->rootfs == NULL || config->rootfs[0] == '\0')
    {
        fprintf(errors, "contained: --rootfs is required\n");
        return CONFIG_PARSE_ERROR;
    }
    if (optind >= argc)
    {
        fprintf(errors, "contained: a command is required after --\n");
        return CONFIG_PARSE_ERROR;
    }
    config->command = &argv[optind];
    return CONFIG_PARSE_OK;
}
