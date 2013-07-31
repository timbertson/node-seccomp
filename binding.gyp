{
  "targets": [
    {
      "target_name": "seccomp_filter",
      "sources": [ "src/seccomp_filter.cc" ],
      "cflags": ["-ggdb", "-fpermissive"],
      "libraries": ["-lseccomp"]
    }
  ]
}
