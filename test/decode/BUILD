cc_library (
	name = "unittest-decode-dep",
	hdrs = glob(["*.h"]),
)

cc_test(
	name = "unittest",
	srcs = glob(["unittest-decode.cc"]),
	deps = [
		"//cicflowmeter-c/decode:decode-dep",
		"//test/decode:unittest-decode-dep",
		"@gtest//:gtest",
		"@gtest//:gtest_main",
	]
)
