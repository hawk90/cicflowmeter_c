load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

cc_library(
	name = "cicflowmeter-dep",
	hdrs = [
		"cicflowmeter.h",
	],
)

cc_binary(
	name = "cicflowmeter",
	srcs = [
		"cicflowmeter.c",
	],
	deps = [
		"//cicflowmeter-c/utils:utils-dep",
		"//cicflowmeter-c/common:common-dep",
		":cicflowmeter-dep",
	],

)
