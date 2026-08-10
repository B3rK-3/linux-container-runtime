/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "config.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int failures;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            ++failures;                                                         \
        }                                                                       \
    } while (0)

static void test_byte_limits(void)
{
    uint64_t value = 0;

    CHECK(config_parse_bytes("1", &value) && value == 1U);
    CHECK(config_parse_bytes("64K", &value) && value == 64U * 1024U);
    CHECK(config_parse_bytes("128MiB", &value) &&
          value == 128U * 1024U * 1024U);
    CHECK(config_parse_bytes("2G", &value) &&
          value == 2ULL * 1024ULL * 1024ULL * 1024ULL);
    CHECK(!config_parse_bytes("0", &value));
    CHECK(!config_parse_bytes("-1", &value));
    CHECK(!config_parse_bytes("1.5G", &value));
    CHECK(!config_parse_bytes("12watts", &value));
    CHECK(!config_parse_bytes("18446744073709551615G", &value));
}

static void test_cpu_limits(void)
{
    struct cpu_limit value = {0};

    CHECK(config_parse_cpu("50000/100000", &value));
    CHECK(value.quota == 50000U && value.period == 100000U);
    CHECK(config_parse_cpu("1000/1000", &value));
    CHECK(!config_parse_cpu("50000", &value));
    CHECK(!config_parse_cpu("0/100000", &value));
    CHECK(!config_parse_cpu("999/100000", &value));
    CHECK(!config_parse_cpu("50000/999", &value));
    CHECK(!config_parse_cpu("50000/1000001", &value));
    CHECK(!config_parse_cpu("1/2/3", &value));
}

static void test_counts_and_hostnames(void)
{
    uint64_t value = 0;

    CHECK(config_parse_count("3", 3U, 10U, &value) && value == 3U);
    CHECK(config_parse_count("10", 3U, 10U, &value) && value == 10U);
    CHECK(!config_parse_count("2", 3U, 10U, &value));
    CHECK(!config_parse_count("11", 3U, 10U, &value));
    CHECK(!config_parse_count("+4", 3U, 10U, &value));
    CHECK(config_valid_hostname("workload-01.example"));
    CHECK(!config_valid_hostname(""));
    CHECK(!config_valid_hostname("-bad"));
    CHECK(!config_valid_hostname("bad/host"));
    CHECK(!config_valid_hostname("bad..host"));
}

static void test_complete_cli(void)
{
    char *arguments[] = {
        "contained", "--rootfs", "/image", "--memory", "32M",
        "--cpu", "25000/100000", "--pids", "12", "--nofile", "48",
        "--hostname", "test-box", "--cgroup-parent", "/cg",
        "--writable-rootfs", "--", "/bin/echo", "ok", NULL,
    };
    int argc = 19;
    struct container_config config;
    FILE *errors = tmpfile();

    CHECK(errors != NULL);
    if (errors == NULL) {
        return;
    }
    optind = 1;
    CHECK(config_parse(&config, argc, arguments, errors) == CONFIG_PARSE_OK);
    CHECK(strcmp(config.rootfs, "/image") == 0);
    CHECK(config.memory_bytes == 32U * 1024U * 1024U);
    CHECK(config.cpu.quota == 25000U && config.cpu.period == 100000U);
    CHECK(config.pids == 12U);
    CHECK(config.nofile == 48U);
    CHECK(config.writable_rootfs);
    CHECK(config.command != NULL && strcmp(config.command[0], "/bin/echo") == 0);
    CHECK(strcmp(config.command[1], "ok") == 0);
    fclose(errors);
}

int main(void)
{
    test_byte_limits();
    test_cpu_limits();
    test_counts_and_hostnames();
    test_complete_cli();

    if (failures != 0U) {
        fprintf(stderr, "%u configuration test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("configuration tests passed");
    return EXIT_SUCCESS;
}
