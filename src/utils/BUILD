load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
	name = "debug-dep",
	srcs = [
		"debug.c",
	],
	hdrs = [
		"debug.h",
		"error.h",
	],
)

#cc_binary(
#	name = "debug",
#	srcs = ["debug.c"],
#	deps = [
#		":debug-dep",
#	],
#)
