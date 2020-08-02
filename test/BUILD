
#cc_test(
#	name = "tests",
#	srcs = glob(["**/*.cc"]),
#	deps = [
#		"//src/utils:debug",
#		"@gtest//:gtest",
#		"@gtest//:gtest_main"
#	]
#)
cc_library (
	name = "test-dep",
	hdrs = ["utils-debug.h"],
)

cc_test(
	name = "unittest",
	srcs = glob(["**/*.cc"]),
	deps = [
		"//cicflowmeter-c/util:util-dep",
		"//test:test-dep",
		"@gtest//:gtest",
		"@gtest//:gtest_main",
	]
)
