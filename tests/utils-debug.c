#include "gtest/gtest.h"
#include "src/utils/debug.h"

TEST(test_case, test_name){
	EXPECT_EQ(LOG_NONSET, -1);
	EXPECT_EQ(DEF_LOG_LEVEL, 5);
}
