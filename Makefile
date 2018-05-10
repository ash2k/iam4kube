ALL_GO_FILES=$$(find . -type f -name '*.go' -not -path "./vendor/*" -not -path "./build/*")
OS = $$(uname -s | tr A-Z a-z)
BINARY_PREFIX_DIRECTORY=$(OS)_amd64_stripped

.PHONY: setup
setup: setup-base
	go get -u golang.org/x/tools/cmd/goimports

.PHONY: setup-base
setup-base:
	dep ensure
	bazel run //:gazelle_fix

.PHONY: fmt-bazel
fmt-bazel:
	bazel build //vendor/github.com/bazelbuild/buildtools/buildifier //vendor/github.com/bazelbuild/buildtools/buildozer
	-bazel-bin/vendor/github.com/bazelbuild/buildtools/buildozer/$(BINARY_PREFIX_DIRECTORY)/buildozer \
		'set race "on"' \
		//:%go_test \
		//cmd/...:%go_test \
		//pkg/...:%go_test
	find . -not -path "./vendor/*" -and \( -name '*.bzl' -or -name 'BUILD.bazel' -or -name 'WORKSPACE' \) -exec \
		bazel-bin/vendor/github.com/bazelbuild/buildtools/buildifier/$(BINARY_PREFIX_DIRECTORY)/buildifier {} +

.PHONY: update-bazel
update-bazel:
	bazel run //:gazelle

.PHONY: build
build: fmt update-bazel build-ci

.PHONY: build-ci
build-ci:
	bazel build //cmd:iam4kube

.PHONY: fmt
fmt:
	goimports -w=true -d $(ALL_GO_FILES)

.PHONY: test
test: fmt update-bazel test-base

.PHONY: verify
verify:
	bazel build //vendor/github.com/bazelbuild/buildtools/buildifier
	find . -not -path "./vendor/*" -and \( -name '*.bzl' -or -name 'BUILD.bazel' -or -name 'WORKSPACE' \) -exec \
		bazel-bin/vendor/github.com/bazelbuild/buildtools/buildifier/$(BINARY_PREFIX_DIRECTORY)/buildifier -showlog -mode=check {} +

.PHONY: test-ci
test-ci: test-base

.PHONY: test-base
test-base:
	bazel test \
		--test_env=KUBE_PATCH_CONVERSION_DETECTOR=true \
		--test_env=KUBE_CACHE_MUTATION_DETECTOR=true \
		-- //... -//vendor/...

.PHONY: quick-test
quick-test:
	bazel test \
		--test_env=KUBE_PATCH_CONVERSION_DETECTOR=true \
		--test_env=KUBE_CACHE_MUTATION_DETECTOR=true \
		--build_tests_only \
		-- //... -//vendor/...

.PHONY: docker
docker: fmt update-bazel
	bazel build \
		--platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
		//cmd/iam4kube:container

# Export docker image into local Docker
.PHONY: docker-export
docker-export: fmt update-bazel
	bazel run \
		--platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
		//cmd/iam4kube:container \
		-- \
		--norun

.PHONY: release
release:
	bazel run \
		--platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
		//cmd/iam4kube:push_docker
	bazel run \
		--platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
		//cmd/iam4kube:push_docker_race
