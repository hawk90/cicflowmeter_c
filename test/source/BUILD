cc_library (
	name = "unittest-source-dep",
	hdrs = glob(["*.h"]),
)

cc_test(
	name = "unittest",
	srcs = glob(["unittest-source.cc"]),
	deps = [
		"//cicflowmeter-c/source:source-dep",
		"//test/source:unittest-source-dep",
		"@gtest//:gtest",
		"@gtest//:gtest_main",
	]
)
