---
layout: post
title:  "2017 Linux Security Summit (Day 2)"
date:   2017-09-25 12:30:00 -0000
tags:   linux security ubuntu lss
---

This post summarizes day two of the
[2017 Linux Security Summit](http://events.linuxfoundation.org/events/linux-security-summit)
(LSS). A post describing the first day can be found [here]({{ site.baseurl }}{% post_url 2017-09-22-2017-Linux-Security-Summit-Day-1 %}).

* TOC
{:toc}

## Hatching Security: LinuxKit as Security Incubator
*Tycho Andersen & Riyaz Faizullabhoy, Docker*

- [Project Page](https://github.com/linuxkit/linuxkit)

LinuxKit provides a way to build Linux distributions that have a slant towards
containers. It will output small Linux container images that are immutable. The
project provides improved security by keeping the images minimal, implementing
signed dependencies, and following best practices for configuration defaults of
installed software components.

Riyaz walked the audience through some technologies that they're using as part
of LinuxKit. He's excited about the potential of the
[Landlock LSM](https://landlock.io/) and spent some time discussing it in the
presentation. He touched on
[Memorizer](https://github.com/linuxkit/linuxkit/tree/master/projects/memorizer)
as a tool that may allow system security policies to be fine-tuned. LinuxKit is
now working with [WireGuard](https://www.wireguard.com/) for a VPN solution.
Finally, [HPE okernel](https://github.com/linux-okernel/linux-okernel) is being
investigated as a way to separate the kernel into differently privileged
partitions.

Tycho has been working on
[eXclusive Page Frame Ownership](https://lwn.net/Articles/700647/) (XPFO) which
protects against ret2dir attacks. The high level idea is to track if the kernel
or userspace owns a given page and to fault if the kernel attempts to
unknowingly use a page owned by userspace. The current implementation is
expensive from a performance standpoint and there are some additional technical
blockers keeping him from completing his work at this time.

## Running Linux in a Shielded VM
*Michael Kelley, Microsoft*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/Running%20Linux%20in%20a%20Shielded%20VM_0.pdf)

A *shielded VM* is a feature of the Hyper-V hypervisor which now supports
Linux guests. Goals of the feature include keeping malicious host admins out of
the guest instances, considering the health of the host before starting VMs,
preventing some storage and network attacks on the VMs, and to utilize
virtualized TPM devices at the guest level to allow for data encryption. The
likely users of the feature are more likely to be virtualization hosting
services rather than desktop or workstation users.

There’s a concept of a *guarded fabric* which includes guarded Hyper-V hosts
and a *host guardian service*. Guests are created from templated disk images
which are basic VM OS templates and a shielding data file that defines the
specifics of a given VM (details include timezone, root password, ssh private
keys, etc.) as configured by the hosting admin.

The host guardian service is a service that would typically be owned by someone
such as the Director of Security for the hosting service. The primary
responsibility of the service is to attest guarded hosts, using a hardware
TPM, and then release keys necessary to launch a shielded VM instance.

The guarded hosts go through a validated boot sequence using a hardware TPM.
Once a guarded host is booted, whitelisting is used to ensure that only
authorized executables can be executed. It is important to note that guarded
hosts provide a vTPM to the shielded VMs that it hosts.

Before shielded VMs are booted, the host guardian service performs remote
attestation of the guarded host that will be hosting the VM. If the guarded
host is in a known good state, the host guardian service releases keys needed
to unlock the vTPM and then unseal the keys needed to decrypt the guest’s
storage prior to booting the guest. The guest’s boot and root partitions are
protected by a signature to detect malicious modifications at boot.

Microsoft strived to not modify shim, grub, or the kernel’s boot process to
support their needs. They achieved this by installing custom UEFI file I/O
protocols in the boot process, resulting in the encrypted boot partition to be
transparently decrypted when grub and shim read from the partition.

The use of a vTPM allows the guests to be migrated anywhere within the guarded
fabric since the vTPM can be moved with it.

The current design does not allow for distro updates to grub or shim to happen
automatically. Manual intervention is required to apply the updates.

[Rackspace](https://www.rackspace.com) and
[brightsolid](https://www.brightsolid.com/) are already hosting shielded
Windows guests. Expect to see shielded Linux guest support to start be deployed
in the wild soon.

## Hallway Session: System Call Interception for Container Managers

The developers of various container managers (LXD, Docker, etc.) are wanting a
way to do some ptrace-like things without using ptrace. They want their
container manager to be consulted whenever processes inside of containers
attempt to perform certain syscalls. Importantly, ptrace must still work inside
of the container in order for things such as GDB to work concurrently. One use
case that was given is that a container process attempting to perform a
`mount()` system call would “trap” out to LXD in order to allow LXD to perform
the mount for the container process. This could be useful in situations where
the container process doesn't have sufficient privileges to perform the mount
itself but LXD knows how to safely handle request. LXD may do trickery such as
mounting a mocked up filesystem to meet the container’s needs. Once LXD
finishes the mount, the container process continues to execute without knowing
that LXD injected itself into the `mount()` operation.

The desired mechanism for providing this functionality is seccomp. The
container manager would load a seccomp filter specifying which syscalls it
wants to trap before starting the container. Seccomp would need to be extended
in a couple different ways to support this including a new action to support
trapping and extended BPF (eBPF) support may also be required.

Nobody has currently agreed to work on the kernel changes for this feature.

## Keys Subsystem
*Dave Howells, Red Hat*

*I was in the hallway session discussed above and could not attend this
subsystem update. The slides have not yet been made available.*

## Protecting VM Register State with AMD SEV-ES
*David Kaplan, AMD*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/AMD%20SEV-ES.pdf)

*This session started very early and I was still busy in the previously
mentioned hallway session.*

## Proposal of a Method to Prevent Privilege Escalation Attacks for Linux Kernel
*Yuichi Nakamura, Hitachi Ltd & Toshihiro Yamauchi, Okayama University*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/nakamura_20170831_1.pdf)

The goal of this work is to prevent privilege escalation attacks through the
Linux kernel’s system call interface. The constraints for the protection is
zero configuration required, a very small performance impact, and a simple
implementation.

A demo was performed on Ubuntu 16.04 LTS running an old kernel that was
vulnerable to
[CVE-2017-6074](https://people.canonical.com/~ubuntu-security/cve/?cve=CVE-2017-6074).
The proof-of-concept exploit *enabled* SELinux on Ubuntu by setting the
`selinux_enforcing` global kernel variable to `1`.

The proposed technical solution is to ensure that kernel level credential
changes do not occur between the system call entry point and exit point of
system calls that are not intended to change credentials. This would
theoretically limit privilege escalation attacks through the system call
interface to only the small subset of calls that are intended to change
privileges. Other security relevant kernel objects, such as the value of the
`selinux_enforcing` variable, could also be compared at system call entry and
exit.

The demo was performed again on a kernel that was updated with their kernel
changes to check credentials at system call entry and exit. Their changes were
sufficient in stopping their previously demoed proof-of-concept.

There’s a large technical issue with their current approach in that the current
users' kernel credentials are stored on the kernel stack at system call entry
and the exploit code could simply modify that stored credential to match what
the exploit wants the credential to be at system call exit. They’re considering
randomizing the stored location but that’s probably not sufficient to stop
attackers.

## SELinux in Android O: Separating Policy to Allow for Independent Updates
*Daniel Cashman, Google*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/LSS%20-%20Treble%20%27n%27%20SELinux_0.pdf)

About 75% (1.5 billion) of the Android devices running today are using SELinux
in enforcing mode. The Android project estimates that SELinux has reduced the
severity of almost half of their kernel bugs.

Android's upcoming Oreo release hopes to greatly reduce the amount of time for
core changes to reach the phones of actual users. Previous Android releases saw
very slow update times and, in many times, updates never reached users. Android
Oreo introduces
[Treble](https://source.android.com/devices/architecture/treble) which means
that non-device-specific changes can be updated on phones in the field without
as much vendor participation.

Treble needed a way to create a more modular Android system so that different
parts of the system could be updated independently of each other. When looking
how to handle security policy updates, SELinux policy modules was a good
thought but there’s language limitations involved with policy modules. They
settled on on-device compilation of the entire combined SELinux policy.

Policy was split into two components: `plat` (framework) and `non_plat` (device
specific). The Sailfish device has about 13.2% of its policy as device-specific
policy while the rest is device agnostic. For anyone not familiar with SELinux
policy, it has strict dependencies on types defined throughout the entire set
of system policy. Types defined in the device specific policy and types defined
in the device agnostic policy have interdependencies yet need to be updated
independently of each other. A policy split of public and private types was
introduced to address this. Attributes were also an important part of the
solution.

A new “assembly-level” SELinux policy language called *Common Intermediate
Language* (CIL) was also created. This opens up the potential for Android to
implement a new higher level policy language, tailored for Android, on top of
CIL in the future.

Android is now leveraging the *neverallow* rule in SELinux policy to ensure
that vendor policy never grants accesses that shouldn’t happen. One example is
a neverallow rule that essentially says, "Don’t let anything in the vendor
partition talk to anything in the system partition without going through a
stable interface." This detects security violations as well as simple
unintended dependencies between the new modular Treble design. The neverallow
checks found 74 bugs in the Treble compliance tests.

## SELinux Subsystem Update
*Paul Moore, Red Hat*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/lss-state_of_selinux-pmoore-092017-r3.pdf)

*I missed the first 5 minutes of this subsystem update due to a hallway session
going too long so my notes start on slide 6.*

There are now build-time assertions that fail the kernel build if a new address
family has been added to the networking subsystem without the list of SELinux
address families being updated. Domain transitions with no-new-privs or nosuid
filesystem mounts now works with an explicit policy rule.

Gitdm shows that 37 different developers have contributed to the kernel code
recently and the same number of developers have contributed to the userspace
code over the same time frame.

Binary policy can now be “disassembled” into Common Intermediate Language to
inspect binary policy.

## AppArmor Subsystem Update
*John Johansen, Canonical Group Ltd.*

- [Slides](https://events.linuxfoundation.org/sites/events/files/slides/lss-apparmor-update-2017_0.pdf)

A large focus has been on an upstreaming effort to eliminate the delta between
the AppArmor features in the Ubuntu kernel and what's in the upstream kernel.
The upstreaming effort is very nearly finished as of 4.14. There’s some
remaining networking mediation work, which is a requirement of `AF_UNIX` and
dbus mediation, that should be ready by 4.15.

AppArmor now supports policy namespaces and stacking multiple policies.
Namespaces are hierarchical and allow containers to load their own AppArmor
policies which is still governed by the host’s AppArmor policy.  There has also
been improvements to apparmorfs in order to better support container workloads.

Future work, for all LSM maintainers, is to work towards generic LSM stacking
so that, for example, AppArmor and SELinux could be stacked together. This
would allow a Fedora container to load SELinux policy while running on an
Ubuntu host that’s using AppArmor policy.

## Seccomp Subsystem Update
*Kees Cook, Google*

- [Slides](https://outflux.net/slides/2017/lss/seccomp.pdf)

Seccomp is a tool to reduce the kernel attack surface. It is used by quite a
few open source projects and is available on all major CPU architectures.

Mike Frysinger made changes to create coredumps when processes are killed with
SIGSYS. Tyler Hicks added dynamic logging support (*watch for a future blog
post on this feature*) to allow administrators and
application developers to have more control over what seccomp actions are
logged. A new action, `SECCOMP_RET_KILL_PROCESS`, has been created to kill the
entire process rather than the specific thread inside of a process. Seccomp
selftests in the kernel have also been improved.

A desired feature request is deep argument inspection so that userspace
pointers can be dereferenced.

## Securing Automated Decryption
*Nathaniel McCallum, Red Hat*

Accessing protected data has historically required a user to enter a password.
Now it is time to automate the process of unlocking encrypted storage so that user intervention is not required in some situation.

The standard encrypted password model is to have a key that protects the data
and key encryption key (KEK), which is typically derived from a passphrase,
that protects the key.

An improvement on this model is to introduce an escrow service to hold an even
stronger KEK that is randomly generated and not based on a passphrase. However,
setting up and maintaining an escrow service is very complex and, due to the
complexity, it may not actually improve data security. There’s authentication
that must be performed, both ways, between the client and the escrow service.
Then there’s backup policy. You must make sure that the service is highly
available. The requirements of a service continue to pile up. Once all the best
practices have been implemented, we end up with a complex system that’s
vulnerable to core attacks, such as Heartbleed, that could leak the key
material that we’ve tried so hard to protect. Key escrow is not an ideal model.

Two engineers at Red Hat developed the McCallum-Relyea (MR) key exchange to
work with a server to construct the necessary decryption key. This new "key
exchange" algorithm allows for the server to not retain key material. There’s
no key exchanged over the wire since the client calculates the key based on
primitives from the server. Authentication and encryption of the communication
transport is optional since no keys are exchanged over the wire.

There’s an important design property to point out here. If an attacker has
access to the encrypted partition and can communicate with the server, the
attacker can derive the key just as the owner of the data is intended to do.

[Tang](https://github.com/latchset/tang) is the server-side daemon that Red Hat
wrote to implement the MR key exchange. It is a small code base that is already
available in Fedora 24 and is being packaged in Debian.

[Clevis](https://github.com/latchset/clevis) is a client that can communicate
with Tang. Clevis allows you to automatically decrypt a LUKS partition,
providing passwordless boot of a system encrypted with dm-crypt.

Shamir’s Secret Sharing mechanism can allow for more complex policy when
unlocking encrypted storage. It allows for a certain threshold of key owners,
or secrets, to be present to unlock the storage. LUKS can be extended to
support Shamir’s Secret Sharing to require, for example, a TPM and either a
password, a Yubikey, Tang-over-network, or Tang-over-bluetooth to unlock laptop
storage.

Future plans for the project include extending Clevis to support
[fscrypt](https://github.com/google/fscrypt) and
[eCryptfs](http://ecryptfs.org/).
