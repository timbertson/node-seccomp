var util = require('./util');
var log = util.log;
var seccomp = require('../../index');
var errno = require('errno');
var fs = require('fs');

seccomp.enter({
	allowed_syscalls: seccomp.whitelist.nodejs,
	default_action: 'trap',
});

var arg = process.argv.slice(2)[0];
switch(arg) {
	case 'ok':
		log('OK');
		break;
	case 'stat':
		log('START');
		fs.statSync('/');
		log('END');
		break;
	default:
		log("UNKNOWN ARG");
		process.exit(20);
		break;
}
