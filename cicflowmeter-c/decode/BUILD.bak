load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
	name = "decode-dep",
	srcs = glob(["*.c"]),
	hdrs = glob(["*.h"]),
	deps = ["//cicflowmeter-c/common:common-dep"],
)
