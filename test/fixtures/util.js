exports.log = function(s) {
	if (s !== undefined) s += "\n";
	else s = "";
	process.stderr.write(s);
};

// process.stderr writestream is
// lazy initted, but doesn't work after seccomp_enter
exports.log();
