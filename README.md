# Linux branches for fuzzing with kAFL

WARNING - this project contains experimental and unsupported software for purpose of research. Do not use for production.

Overview:

* `guest` tracks upstream TDX guest kernel at https://github.com/intel/tdx/
* `kafl/fuzz-N` are variants of guest kernel for fuzzing with kAFL
* `kafl/sdv-N` are variants of host kernel with TDX 'SDV' emulation + kAFL support

See also:
* [IntelLabs/kAFL](https://github.com/IntelLabs/kAFL)
* [KVM-Nyx](https://github.com/nyx-fuzz/KVM-Nyx)
