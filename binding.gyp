{
  "targets": [
    {
      "target_name": "seccomp_filter",
      "sources": [ "seccomp_filter.cc" ],
      "cflags": ["-ggdb", "-fpermissive"],
      "libraries": ["-lseccomp"]
    }
  ]
}
