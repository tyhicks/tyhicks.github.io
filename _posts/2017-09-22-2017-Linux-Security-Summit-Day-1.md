---
layout: post
title:  "2017 Linux Security Summit (Day 1)"
date:   2017-09-22 22:47:50 -0000
tags:   linux security ubuntu lss
---

The [2017 Linux Security Summit](http://events.linuxfoundation.org/events/linux-security-summit) (LSS)
was held from September 14th through 15th in downtown Los Angeles. There were
just short of 175 attendees and the talks were all quite interesting. I'd
highly recommend attending the next LSS if you're interested in any aspect of
security in Linux.

I took notes throughout the event and, in some cases, John Johansen pitched in
and filled in the holes in my notes. This post summarizes the first day of the
conference. Be sure to check out the [day two notes]({{ site.baseurl }}{% post_url 2017-09-22-2017-Linux-Security-Summit-Day-2 %}), as well.

I tried to capture as much technical detail as possible. If you want a more
concise summary of the sessions, have a look at Paul Moore's
[2017 LSS Notes](http://www.paul-moore.com/blog/d/2017/09/linux-security-summit.html).

* TOC
{:toc}

## ARMv8.3 Pointer Authentication
*Mark Rutland, ARM Ltd.*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/slides_23.pdf)
- [LWN Article](https://lwn.net/Articles/718888/)

There has been a focus on code reuse attacks which do have protections but
those protections are not always deployed. Pointer authentication is an
optional ARMv8.3-A extension that detects illicit modification of pointers and
data structures that can be transparently enabled in some cases.

There are new instructions, in the CPU instruction set, to sign and
authenticate pointers. For example, these new instructions could ensure that a
return address is valid only for a given stackframe. The pointer authentication
codes (PAC), which are embedded into the pointer itself, do not require
additional space overhead to store a pointer. Each PAC is derived from a
pointer value, 64-bit context value, and a 128-bit secret key. The PAC
algorithm can be [QARMA](https://tosc.iacr.org/index.php/ToSC/article/view/583)
or something else that is implementation defined. The PAC is stored in the
RESERVED area of the pointer (size varies based on kernel config but the
AArch64 defconfig results in 7 bits for the PAC).

The instructions are automatically inserted into a function prologue/epilogue,
by the compiler, so application developers don’t have to think about PAC. A
derefence operation would result in a fault if the authentication operation
fails.  The result of the dereference will result in an address in memory that
is architecturally guaranteed to be an unmapped address.

A piece of code that contains a buffer overflow issue and is vulnerable to a
ROP attack could have its return address overwritten without detection. With
the paciasp instruction inserted into the prologue and the autiasp instruction
inserted into the epilogue, the [link register](https://en.wikipedia.org/wiki/Link_register)
containing the return address is automatically authenticated upon function
return.

A really nice property is that these two instructions are backwards compatible
and simply no-ops in older ARM processors. There are more flexible instructions
that allow things such as JITs to specify various registers, other than the
link register, and those are not backwards compatible.

In Linux, there’s a per-process APIAKey that’s initialized at exec() and is
retained across fork(). One downside is that this means that there’s no way to
authenticate shared memory regions that are shared between unrelated processes.
GCC version 7 already supports `-msign-return-address` to use the APIAKey and
backwards compatible instructions by default. The current implementation only
works for userspace PAC but support for kernel PAC is in progress.

## Defeating Invisible Enemies: Firmware Based Security in the OpenPOWER Platform
*George Wilson, IBM*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/op-stboot-lss-2017-v7.0.pdf)

IBM is working on providing secure boot and trusted boot in OpenPOWER machines.
This effort will ensure that OpenPOWER is on par with UEFI from the standpoint
of secure boot protections.

A new OpenPOWER foundation allows a number of partners to define what the
OpenPOWER firmware is. The goal is to reuse as much existing open source
software as possible and only maintain the POWER specific bits in an entirely
open source manner. OpenPOWER runs an open source firmware and the KVM
hypervisor with Linux guests and the OpenPOWER Foundation hosts the firmware on
[GitHub](https://github.com/open-power).

[Petitboot](http://git.ozlabs.org/?p=petitboot) is used exclusively, not grub,
to act as the operating system bootloader. The design around the boot
verification process is based on an attempt to map the Trusted Computing Group
(TCG) PC Client and UEFI Specifications as best as possible to OpenPOWER. This
work may drive changes for new TCG specifications to fill in holes that were
identified in the existing spec.

Skiroot is the transition point between firmware and software measurements.
Skiroot is a Linux kernel that contains an embedded initramfs that runs
Petitboot from init. Petiboot launches the host OS payload kernel via kexec,
which is already instrumented to measure a kernel, meaning that the
verification code could be reused. The
[Linux Integrity Subsytem](http://linux-ima.sourceforge.net) (IMA) does the
work of verifying the measurements of the boot components in Skiroot. The IMA
event log is passed to the payload kernel via `kexec_file_load()`. IBM
Research’s TPM 2.0 TSS is currently used in skiroot.

Future work may allow for remote attestation of the skiboot. There’s currently
a proof-of-concept based on IBM Research’s attestation project but there may be
a move to Intel’s implementation in the future.

A hardware design limitation of the OpenPOWER platform is that there’s no
secure, dynamically lockable storage built in. However, a TPM device provides
NVRAM for a small amount of secure storage.

IBM’s signing keys are maintained on an IBM 4767 HSM and they’re encouraging
their original design manufacturers (ODMs) to do something similar to ensure
that their signing keys remain secure.

The OS kernel is signed with the sign-file tool, which is what’s used to sign
Linux kernel modules today. RSA-2048 with SHA-256 is used to match what’s being
done by UEFI which allows reusing existing UEFI shim keys. The initramfs is not
signed because it is volatile but IMA-appraisal could be used in the future. 

There’s no central CA and no shim which allows the admin to be in full control
of the system. This allows for three scenarios:
1. Administrator builds and signs his/her own OS
2. Administrator configures trusted keys to boot an existing Linux distribution
3. Manufacturer configures trusted distribution keys before shipment

Virtual TPMs are not supported yet but this will be necessary in the future to
extend trust to guest operating systems.

## Landlock LSM: Toward Unprivileged Sandboxing
*Mickaël Salaün*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/2017-09-14_landlock-lss.pdf)
- [Project page](https://landlock.io/)

Landlock is trying to fill a void left by various Linux Security Modules
(AppArmor, SELinux, SMACK, etc.), seccomp, and Linux namespaces. An application
developer that wants to build a security sandbox in Linux today can't turn to
just one of those tools to do so. Mickaël points out that none of those tools,
on their own, allows for fine-grained access control, security policy embedded
into the application, and unprivileged use.

Landlock is designed to provide all three features to be a complete application
sandboxing solution that allows the application developer to create access
control tailored to his/her application.

The Landlock v7 patchset is minimal and only implements just enough to validate
the design. It is a stackable LSM that uses eBPF and is currently focused on
file accesses. The Landlock eBPF policy for a given application is embedded
into the source code of the application and the application must load it into
the kernel when the application is launched.

Landlock uses rules that make decisions based on an object (termed as an event)
and action (read, write, etc.). It uses the `seccomp()` syscall to restrict the
process by appending its eBPF rules to the seccomp rule set. The various LSM
hooks that Landlock implements will look at the seccomp event which triggered
the LandLock eBPF rule and make its decision on whether the action should be
allowed.

Rules are inherited across process `fork()` in exactly the same way that
existing seccomp rules are inherited by children processes. A child process can
append new rules to further restrict itself and its children but not its
siblings.

## The State of Kernel Self-Protection
*Kees Cook, Google*

- [Slides](https://outflux.net/slides/2017/lss/kspp.pdf)
- [Project Page](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)

Kernel self protection project (KSPP) is intended to protect the kernel from
userspace process. Kernel bug lifetimes are longer than ever now because the
Linux kernel is running on a large number of embedded devices (cars, TVs, etc.)
that remain in use for very long amounts of time. Self protection features are
absolutely necessary to keep products secure after the support lifetimes have
expired.

Attackers are watching incoming kernel commits to identify security
vulnerabilities potentially long before they’re discovered by the “good guys”.
The good guys have some tools to find them, such as static and dynamic
checkers, and the discovered bugs are being fixed but attackers have the same
resources and even more motivation to discover the flaws. In comparison to
automobile safety, the Linux kernel is stuck in the 50’s and is missing
important safeguards such as crumple zones, airbags, etc.

The goal of the project is to kill entire bug classes across the entire kernel
rather than reactively fixing an individual flaw in a single subsystem of the
kernel source tree.

Many exploit mitigations already exist (such as what is provided in
grsecurity/Pax) or have been researched but there’s still a lot of room for
improvement in bringing out-of-tree defenses into the upstream Linux kernel.
Some downstream kernel forks of security features include Red Hat’s ExecShield,
Ubuntu’s AppArmor patches, Android’s Samsung KNOX, and grsecurity.

Bringing existing out-of-tree defenses into the upstream Linux kernel benefits
all users of the Linux kernel. Additionally, the process of upstreaming the
out-of-tree defense technologies has the potential to improve the technologies
even more and possibly uncover holes in the protection techniques.

About 12 organizations and 10 additional individuals are currently involved in the KSPP project.

Bug classes that are being targeted include:
* Stack overflow and exhaustion
* Integer over/underflow
* Buffer overflows
* Format string injection
* Kernel pointer leaks
* Uninitialized variables
* Use-after-free
* Direct kernel memory overwrites
* Userspace execution
* Userspace data
* Reused code chunks (ROP, JOP, etc.)

Kees points out cultural challenges as a major challenge for KSPP. Upstream is
conservative on hardening features that are accepted and some kernel developers
don’t necessarily acknowledge the need for hardening. Out-of-tree developers
are sometimes unaware of the upstream kernel inclusion process and don't get
involved because of this. The hope is that the KSPP project can bridge the gap
and continue to bring new protections into the upstream kernel.

## Confessions of a Security Hardware Driver Maintainer
*Gilad Ben-Yossef, ARM*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/gby_confession_LSS_2017_2.pdf)

*I missed the start of this presentation due to being involved in a hallway
session. Please see the slides for details.*

## CII Best Practices Badge, 1.5 Years Later - David Wheeler, IDA
*David Wheeler, IDA*

- [Project Page](https://bestpractices.coreinfrastructure.org/)

The Linux Foundation created the Core Infrastructure Initiative (CII) in 2014
to fund critical projects that many organizations and users rely on but were
not receiving adequate funding.

The CII announced a badging project May, 2016, to identify open source projects
that followed a best practices criteria. There are estimated to be over 3
million open source projects in the wild so the project would need to widely
scale to support a potentially large number of applicants. To achieve this, a
web application was created to allow project maintainers to self-certify their
projects. There's no cost for maintainers to see if their projects meet the
criteria. There are now three badge levels (passing, silver, and gold) that are
given out based on 66 different criteria. Some of the criteria is suggested and
others are required.

An interesting observation is that OpenSSL, which now has a passing badge, only
met one third of the criteria before [Heartbleed](http://heartbleed.com/) was
discovered.

There are now over 100 software projects that have passing badges and another
1,000 participating projects. Participating projects are constantly modifying
their processes to meet badge requirements which shows a positive affect on the
open source ecosystem.

Out of the projects that meet 90% of the criteria but still don't have a
passing badge, the number one reason is due to their lack of publishing
instructions for reporting vulnerabilities found in their project. The second
is due to the lack of HTTPS usage in their project's hosting services.

## The Smack 10th Year Update
*Casey Schaufler, Intel*

The SMACK LSM has reached its 10 year anniversary. It still prides itself for
remaining simple after all these years even after being extended for Tizen and
Automotive Grade Linux.

Feature development has slowed over the last year (one new feature) and the
majority of the work has been on bug fixing. There’s some current work in
progress around the default labeled network configuration. The SMACK backlog
includes Calipso, a TCP race condition bug fix, infiniband, overlayfs, libvirt,
and eBPF support.

## Integrity Subsystem Update
*Mimi Zohar, IBM*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/LSS2017-LinuxIntegritySubsystemStatus.pdf)

The Linux kernel integrity subsystem’s goal is to detect if files have been
accidentally or maliciously altered, appraise a file’s measurement or
signatures, and enforce local file integrity. The integrity subsystem has been
pulled in a number of different directions recently yet those goals remain
unchanged.

Mimi says that the technology to extend secure boot’s root of trust into the
OS, via IMA-measurement and IMA-appraisal, is now available but coordination
with the various distros to include file measurements in packaging is needed.

IMA-audit was added in Linux kernel version 3.10 by Peter Moody to audit file
measurements. Other new features include carrying the measurement list across
kexec (4.10), embedding IMA more deeply into the VFS layer, appended signature
support for kernel modules (*modsig*), and the platform keyring for using UEFI
keys for verifying a kernel image.

## TPM Subsystem Update
*Jarkko Sakkinen, Intel Corporation*

*I do not have comprehensive notes for this session and, at the time of
writing, the slides have not been made available.*

## BoF: Extreme Security Module Stacking - Issues and Directions
*Casey Schaufler, The Smack Project*

There's a push among some in the Linux kernel security community to allow for
multiple Linux Security Modules (LSMs) to be "stacked". This would allow, for
example, AppArmor and SELinux to both be enabled at the same time and for each
LSM to have a say in whether a process should be able to carry out a given
action. The need to stack multiple LSMs is largely derived from container
workloads where, for example, Ubuntu and AppArmor are used in the host
environment and a Red Hat Enterprise Linux (RHEL) container is launched. The
RHEL container would strongly prefer to use SELinux to restrict access inside
of the container yet the Ubuntu host environment still wants to confine the
container, as a whole, with AppArmor policy.

Casey started the session by demonstrating that the SELinux test suite passes,
with the exception of expected failure in the labeled networking tests, on
Fedora when SELinux and SMACK are stacked together using the LSM stacking
kernel patches that he's been developing for a number of years.

There are a few external kernel interfaces that pose a serious problem to LSM
stacking. Existing applications, such as `ps`, directly read from
`/proc/<PID>/attr/current` to get the security context of a process. The
current format of that virtual file is a single security context in a string
form but LSM stacking introduces the need to map multiple security contexts
(one for each stacked LSM) to a single process. The same holds true for the
`SO_PEERSEC` option supported by `getsockopt()` which is used by userspace
projects such as `dbus-daemon`.

Casey proposes that the kernel should track the *display LSM* of each process.
When the process attempts to use one of these legacy interfaces that were only
designed for a single security context, the interface will operate according to
the currently selected display LSM. The `prctl()` system call can be used to
switch to a different LSM in order for the process to see the security context
of each stacked LSM. The display LSM will be inherited by children processes.

Additionally, a new `/proc/<PID>/attr/<LSM>/` directory will be created to
provide unambiguous information regarding a each LSM. To support fetching the
security context from each LSM without having to iterate through various
`/proc/<PID>/attr/<LSM>` directories, a special `/proc/<PID>/attr/context` file
will be provided to display all LSM security contexts at once using the format
of `lsm-name='lsm-data'[,lsm-name='lsm-data']...`.

The question was raised as to why add the new `prctl()` operation at all since
newly authored code will use the new combined interfaces and legacy code won't
know about the `prctl()` operation. There are two reasons to provide such a
mechanism:
1. It allows for a parent process to set the display LSM for its children
   where the child process may be legacy code while the parent's code is newly
   written.
2. The `SO_PEERSEC` interface is not so easy to replace, its not as simple as
   just adding new virtual files.

The privileges required to set the display LSM was also questioned. If an
application intends to handle a security context from a specific LSM but
unexpectedly gets the security context from a different LSM, the context may
still look valid and result in an incorrect mediation decision. It could also
be possible that the display LSM could deliberately be set by a malicious
application to circumvent mediation. This could happen if the malicious
application can ptrace and set a different display LSM.

The general consensus was that the display LSM should be reset when executing
setuid applications. There was not a clear answer as to whether elevated
privilege should be required to set one's own display LSM but there are
situations where an unprivileged application, such as the `dbus-daemon` session
bus, may need to cycle through different display LSMs.

To address the `SO_PEERSEC` problem, a new socket option that either allows
specifying the desired LSM context or a compound context like provided by
`/proc/<PID>/attr/context` file could be a better solution. New applications
could use the new option to avoid any problems.

The LSM developers also need to determine how to handle *secids* which are a
global 32-bit handle. Casey's current pathces provide a basic mapping of secids
to an ID in the new LSM stacking infrastructure. The patch is incomplete and
still needs to sort out locking and secid lifetime issues.

## BoF: Namespacing LSM Subsystems
*John Johansen, Canonical Group Ltd.*

LSM namespacing is very closely tied to LSM stacking which is mentioned in the
previous section. The example given above where a host environment using
AppArmor and a container using SELinux requires both LSM stacking and LSM
namespacing.

There were two use cases discussed for namespacing the LSMs:
1. Parallel LSMs
2. Stacked LSMs

The use case for being able to use LSMs in parallel, where a thin OS layer like
CoreOS is used and each container lives in parallel, was discussed. The problem
with this is that if there is a means to switch the LSMs into a parallel state,
instead of a stacked state, it could be potentially be used in an attack vector
to escape LSM confinement. The general consensus was that this use case is not
a strong requirement and should not be initially supported.

The stacked LSM use case is targeted at allowing containers using an alternate
LSM to run on a host that wants to enforce its LSM restrictions. Stacked
namespacing of the LSM has all the same problems as stacking the LSM and
introduces a few new issues.

There were questions about how the LSM namespace should be initialized as
neither AppArmor nor SELinux want it tied to cgroups or user namespaces.
Possibilities included allowing new LSM namespaces to be requested via
`clone()` and `unshare()` or some other mechanism. There was no resolution to
this topic but it is worth noting that AppArmor has its own private interface
for namespace creation in its securityfs implementation.

Another interesting problem comes from the fact that some LSMs use extended
attributes on filesystem inodes to store security contexts. As multiple LSMs
are stacked together, the amount of storage and filesystem accesses will
increase to store the combination of required extended attributes.
