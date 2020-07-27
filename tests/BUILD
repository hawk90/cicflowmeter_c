
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
	name = "tests-dep",
	hdrs = ["utils-debug.h"],
)

cc_test(
	name = "tests",
	srcs = glob(["**/*.cc"]),
	deps = [
		"//src/utils:debug-dep",
		"//tests:tests-dep",
		"@gtest//:gtest",
		"@gtest//:gtest_main",
	]
)
