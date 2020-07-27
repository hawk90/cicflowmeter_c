#include "gtest/gtest.h"
#include "src/utils/debug.h"

TEST(test_case, test_name){
	EXPECT_EQ(LOG_NOTSET, -1);
	EXPECT_EQ(DEF_LOG_LEVEL, 5);
}
