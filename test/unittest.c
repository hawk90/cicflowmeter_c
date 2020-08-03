#include <gtest/gtest.h>
#include "utils-debug.h"

TEST(debugger_test, log_level)
{
	EXPECT_EQ(LOG_NOTSET, -1);
}
