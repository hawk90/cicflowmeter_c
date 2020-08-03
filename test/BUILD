cc_library (
	name = "test-dep",
	hdrs = ["unittest.h"],
)

cc_test(
	name = "unittest",
	srcs = glob(["unittest.cc"]),
	deps = [
		"//cicflowmeter-c/util:util-dep",
		"//test:test-dep",
		"@gtest//:gtest",
		"@gtest//:gtest_main",
	]
)
