load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(default_visibility = ["//visibility:public"])

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
		"//cicflowmeter-c/utils:debug-dep",
		":cicflowmeter-dep",
	],

)
