
# What is it?

It's a node extension to enable seccomp filtering, based on
the [seccomp_filter](https://github.com/vi/syscall_limiter/)
program by Vitaly Shukela.

# Yeah, but what _is_ it?

[seccomp][doc] is a simple sandboxing mechanism for the linux kernel.
If after reading that document you still don't get why you'd use it, you
probably have no need to.

[doc]: http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/prctl/seccomp_filter.txt?id=HEAD

# Licence

MIT

# Requires:

 * libseccomp-devel (rpm)
 * libseccomp-dev (deb)
