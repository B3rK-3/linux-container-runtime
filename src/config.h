/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CONTAINED_CONFIG_H
#define CONTAINED_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define CONTAINED_DEFAULT_MEMORY (256ULL * 1024ULL * 1024ULL)
#define CONTAINED_DEFAULT_CPU_QUOTA 50000ULL
#define CONTAINED_DEFAULT_CPU_PERIOD 100000ULL
#define CONTAINED_DEFAULT_PIDS 64ULL
#define CONTAINED_DEFAULT_NOFILE 256ULL
#define CONTAINED_DEFAULT_CGROUP_PARENT "/sys/fs/cgroup"

struct cpu_limit {
    uint64_t quota;
    uint64_t period;
};

struct container_config {
    const char *rootfs;
    const char *hostname;
    const char *cgroup_parent;
    uint64_t memory_bytes;
    struct cpu_limit cpu;
    uint64_t pids;
    uint64_t nofile;
    bool writable_rootfs;
    char **command;
};

enum config_parse_result {
    CONFIG_PARSE_OK = 0,
    CONFIG_PARSE_HELP = 1,
    CONFIG_PARSE_ERROR = 2,
};

void config_init(struct container_config *config);
enum config_parse_result config_parse(struct container_config *config,
                                      int argc,
                                      char **argv,
                                      FILE *errors);
void config_print_usage(FILE *stream, const char *program);

bool config_parse_bytes(const char *text, uint64_t *value);
bool config_parse_cpu(const char *text, struct cpu_limit *value);
bool config_parse_count(const char *text,
                        uint64_t minimum,
                        uint64_t maximum,
                        uint64_t *value);
bool config_valid_hostname(const char *hostname);

#endif
