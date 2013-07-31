var _mod = require('./build/Release/seccomp_filter.node');
for (var k in _mod) {
	if (_mod.hasOwnProperty(k)) {
		exports[k] = _mod[k];
	}
};
var wl = exports.whitelist = {};

wl.minimal = [
	"read",
	"write",
	"exit",
	"rt_sigreturn",
];

wl.memory = [
	'mmap',
	'brk',
	'munmap',
	'madvise',
];

wl.stream = [
	'lseek',
	'close',
	'fstat',
];

wl.process = [
	'exit_group',
];

wl.events = [
	'futex',
	'nanosleep',
	'epoll_wait',
	'epoll_ctl',
];

function concat() {
	var a = [];
	for (var i=0; i<arguments.length; i++) {
		a = a.concat(arguments[i]);
	}
	return a;
}

wl.nodejs = concat(wl.minimal, wl.memory, wl.stream, wl.events, wl.process);
