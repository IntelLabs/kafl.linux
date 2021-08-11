#!/bin/bash

# this builds and installs just the kvm kmod
# assumption is that full kAFL kernel was already build and is currently running (!)

# quick sanity check
uname -r |grep -iq tdfl || exit
test -d /lib/modules/$(uname -r)/kernel/arch/x86/kvm/ || exit

make -j $(nproc) M=arch/x86/kvm
sudo cp arch/x86/kvm/kvm{,-intel}.ko /lib/modules/$(uname -r)/kernel/arch/x86/kvm/
sudo depmod -a
sudo rmmod kvm_intel kvm
sudo modprobe kvm
sudo modprobe kvm_intel ve_injection=1 halt_on_triple_fault=1
