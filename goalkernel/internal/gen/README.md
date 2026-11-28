# Extracted goal kernel (generated, do not edit)

This directory holds the Go translation of the Dafny-proved goal compiler (`formal/dafny/Goal.dfy` in the flagship repository),
produced with the pinned Dafny (`formal/dafny/TOOLCHAIN.lock`) by `formal/dafny/build-native.sh go`: one package per Dafny module
plus the Dafny runtime (`dafny`, `System_`), with their imports rewritten to this module's path.
CI produces it: the "Goal kernel native extractions" workflow translates the same sources, fails when the files committed here
differ from a fresh translation, and uploads the fresh translation as an artifact to commit.

Package `goalkernel` imports it. Because it is generated, `goalkernel` and its tests build only with the tag `pcagoalkernel`
(`go test -tags pcagoalkernel ./goalkernel/`), so `go build ./...` keeps working while this directory holds only the README.
Only this README is written by hand; `build-native.sh` keeps it and replaces every other file.
