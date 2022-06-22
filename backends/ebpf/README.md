# KPNG EBPF Backend Implementation

## Intro

This KPNG ebpf based backend is currently a POC and is limited in functionality
exclusively to proxying for ClusterIP based services.

## Compile ebpf program

This will automatically use cillium/ebpf to compile the go program into bytecode
using clang, and build go bindings

`go generate`

## Start a local kpng ebpf backend kind cluster

`./hack/test_e2e.sh -i ipv4 -b ebpf -d`

## See ebpf program logs

`kubectl logs -f <KPNG_POD_NAME> -n kube-system -c kpng-ebpf-tools`

## Licensing

The user space components of this example are licensed under the [Apache License, Version 2.0](/LICENSE) as is the
rest of the code defined in KPNG.

The bpf code template (defined in [`cgroup_connect3.c`](/backends/ebpf/bpf/cgroup_connect4.c)) was adapted from
the bpf templates defined in the [Cilium Project](https://github.com/cilium/cilium) and
continues to use one of the same licenses defined there, i.e the [2-Clause BSD License](/backends/ebpf/bpf/LICENSE.BSD-2-Clause).
