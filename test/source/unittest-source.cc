#include <climits.h>

#include "unittest-source.h"


static uint32_t upper32(uint64_t value)
{
    return (uint32_t)(value >> 32);
}
static uint32_t lower32(uint64_t value)
{
    return (uint32_t)value;
}

typedef struct TestData_ {
    uint64_t last;
    u_int current;
} TEST_DATA_T;

static int update_pcap_stats_value64_nochange01(void)
{
    TEST_DATA_T data[] = {{.last = 0, .current = 0},
            {.last = 12345, .current = 12345},
            {.last = (uint64_t)UINT32_MAX, .current = UINT_MAX}};

    for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
        FAIL_IF_NOT(data[i].last == data[i].current);

        UpdatePcapStatsValue64(&data[i].last, data[i].current);
        FAIL_IF_NOT(data[i].last == data[i].current);
    }

    PASS;
}

static int UpdatePcapStatsValue64NoChange02(void)
{
    /*
     * No change in counter values.
     * Last count is outside 32bits range.
     */
    TestData data[] = {{.last = (2ull << 32) + 0, .current = 0},
            {.last = (3ull << 32) + 12345, .current = 12345},
            {.last = (3ull << 32) + (uint64_t)UINT32_MAX, .current = UINT_MAX},
            {.last = UINT64_MAX, .current = UINT_MAX}};

    for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
        uint32_t upper = Upper32(data[i].last);
        FAIL_IF_NOT(Lower32(data[i].last) == data[i].current);

        UpdatePcapStatsValue64(&data[i].last, data[i].current);
        FAIL_IF_NOT(Lower32(data[i].last) == data[i].current);
        FAIL_IF_NOT(Upper32(data[i].last) == upper);
    }

    PASS;
}

static int UpdatePcapStatsValue64NoOverflow01(void)
{
    /*
     * Non-overflowing counter value is simply taken over in lower 32bits.
     * Last count is within first 32bit range, i.e. same as pcap_stat range.
     * Also test edges and simple +1.
     */
    TestData data[] = {{.last = 0, .current = 1},
            {.last = 12345, .current = 34567},
            {.last = (uint64_t)UINT32_MAX - 1, .current = UINT_MAX}};

    for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
        FAIL_IF_NOT(data[i].last < data[i].current);

        UpdatePcapStatsValue64(&data[i].last, data[i].current);
        FAIL_IF_NOT(data[i].last == data[i].current);
    }

    PASS;
}

static int UpdatePcapStatsValue64NoOverflow02(void)
{
    /*
     * Non-overflowing counter value is simply taken over in lower 32bits.
     * Last count is outside 32bits range.
     */
    TestData data[] = {{.last = (2ull << 32) + 0, .current = 1},
            {.last = (3ull << 32) + 12345, .current = 34567},
            {.last = UINT64_MAX - 1, .current = UINT_MAX}};

    for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
        uint32_t upper = Upper32(data[i].last);
        FAIL_IF_NOT(Lower32(data[i].last) < data[i].current);

        UpdatePcapStatsValue64(&data[i].last, data[i].current);
        FAIL_IF_NOT(Lower32(data[i].last) == data[i].current);
        FAIL_IF_NOT(Upper32(data[i].last) == upper);
    }

    PASS;
}

static int UpdatePcapStatsValue64Overflow01(void)
{
    /*
     * Overflowing counter value is simply taken over in lower 32bits.
     * Last count is within first 32bit range, i.e. same as pcap_stat range.
     */
    TestData data[] = {{.last = 1, .current = 0},
            {.last = 12345, .current = 22}, {.last = 12345, .current = 12344},
            {.last = (uint64_t)UINT32_MAX, .current = UINT_MAX - 1}};

    for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
        FAIL_IF_NOT(data[i].last > data[i].current);

        UpdatePcapStatsValue64(&data[i].last, data[i].current);
        FAIL_IF_NOT(Lower32(data[i].last) == data[i].current);
        FAIL_IF_NOT(Upper32(data[i].last) == 1); /* wrap around */
    }

    PASS;
}

static int UpdatePcapStatsValue64Overflow02(void)
{
    /*
     * Overflowing counter value is simply taken over in lower 32bits.
     * Last count is outside 32bits range.
     */
    TestData data[] = {{.last = (2ull << 32) + 1, .current = 0},
            {.last = (3ull << 32) + 12345, .current = 22},
            {.last = (3ull << 32) + 12345, .current = 12344},
            {.last = UINT64_MAX, .current = UINT_MAX - 1}};

    for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
        uint32_t upper = Upper32(data[i].last);
        FAIL_IF_NOT(Lower32(data[i].last) > data[i].current);

        UpdatePcapStatsValue64(&data[i].last, data[i].current);
        FAIL_IF_NOT(Lower32(data[i].last) == data[i].current);
        FAIL_IF_NOT(Upper32(data[i].last) == upper + 1); /* wrap around */
    }

    PASS;
}

static int UpdatePcapStatsValue64Overflow03(void)
{
    /*
     * Overflowing counter value is simply taken over in lower 32bits.
     * Edge cases where upper32 bit wrap around to 0.
     */
    TestData data[] = {{.last = UINT64_MAX, .current = 0},
            {.last = UINT64_MAX, .current = 3333}};

    for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
        FAIL_IF_NOT(Lower32(data[i].last) > data[i].current);

        UpdatePcapStatsValue64(&data[i].last, data[i].current);
        FAIL_IF_NOT(Lower32(data[i].last) == data[i].current);
        FAIL_IF_NOT(Upper32(data[i].last) == 0); /* wrap around */
    }

    PASS;
}

static int UpdatePcapStats64Assorted01(void)
{
    /*
     * Test that all fields of the struct are correctly updated.
     *
     * Full testing of value behaviour is done in UpdatePcapStatsValue64...()
     * tests.
     */
    PcapStats64 last = {.ps_recv = 0, .ps_drop = 1234, .ps_ifdrop = 8765};
    struct pcap_stat current = {
            .ps_recv = 12, .ps_drop = 2345, .ps_ifdrop = 9876};

    // test setup sanity check
    FAIL_IF_NOT(last.ps_recv < current.ps_recv);
    FAIL_IF_NOT(last.ps_drop < current.ps_drop);
    FAIL_IF_NOT(last.ps_ifdrop < current.ps_ifdrop);

    UpdatePcapStats64(&last, &current);

    FAIL_IF_NOT(last.ps_recv == current.ps_recv);
    FAIL_IF_NOT(last.ps_drop == current.ps_drop);
    FAIL_IF_NOT(last.ps_ifdrop == current.ps_ifdrop);

    PASS;
}
