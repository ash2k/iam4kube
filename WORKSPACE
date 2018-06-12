load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "c1f52b8789218bb1542ed362c4f7de7052abcf254d865d96fb7ba6d44bc15ee3",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/0.12.0/rules_go-0.12.0.tar.gz"],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "ddedc7aaeb61f2654d7d7d4fd7940052ea992ccdb031b8f9797ed143ac7e8d43",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/0.12.0/bazel-gazelle-0.12.0.tar.gz"],
)

http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "f099d84a638ceaf5947bb227100d96c879681cc0f384d0d0cd0f5fb876798124",
    strip_prefix = "rules_docker-e5ebe3d241775a220e37aceaa24c3e78700a4e0b",
    urls = ["https://github.com/bazelbuild/rules_docker/archive/e5ebe3d241775a220e37aceaa24c3e78700a4e0b.zip"],
)

http_archive(
    name = "distroless",
    strip_prefix = "distroless-813d1ddef217f3871e4cb0a73da100aeddc638ee",
    urls = ["https://github.com/GoogleCloudPlatform/distroless/archive/813d1ddef217f3871e4cb0a73da100aeddc638ee.zip"],
)

load("@distroless//package_manager:package_manager.bzl", "dpkg_src", "dpkg_list", "package_manager_repositories")
load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")
load(
    "@io_bazel_rules_docker//go:image.bzl",
    go_image_repositories = "repositories",
)
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

go_rules_dependencies()

go_register_toolchains()

go_image_repositories()

gazelle_dependencies()

package_manager_repositories()

# Stuff below was copied from https://github.com/GoogleCloudPlatform/distroless/blob/master/WORKSPACE

dpkg_src(
    name = "debian_stretch",
    arch = "amd64",
    distro = "stretch",
    sha256 = "4cb2fac3e32292613b92d3162e99eb8a1ed7ce47d1b142852b0de3092b25910c",
    snapshot = "20180406T095535Z",
    url = "http://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian_stretch_backports",
    arch = "amd64",
    distro = "stretch-backports",
    sha256 = "2863af9484d2d6b478ef225a8c740dac9a14015a594241a0872024c873123cdd",
    snapshot = "20180406T095535Z",
    url = "http://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian_stretch_security",
    package_prefix = "http://snapshot.debian.org/archive/debian-security/20180405T165926Z/",
    packages_gz_url = "http://snapshot.debian.org/archive/debian-security/20180405T165926Z/dists/stretch/updates/main/binary-amd64/Packages.gz",
    sha256 = "a503fb4459eb9e862d080c7cf8135d7d395852e51cc7bfddf6c3d6cc4e11ee5f",
)

dpkg_list(
    name = "iptables_bundle",
    packages = [
        "iptables",
        "libip4tc0",
        "libip6tc0",
        "libiptc0",
        "libnetfilter-conntrack3",
        "libnfnetlink0",
        "libxtables12",
    ],
    # Takes the first package found: security updates should go first
    # If there was a security fix to a package before the stable release, this will find
    # the older security release. This happened for stretch libc6.
    sources = [
        "@debian_stretch_security//file:Packages.json",
        "@debian_stretch_backports//file:Packages.json",
        "@debian_stretch//file:Packages.json",
    ],
)
