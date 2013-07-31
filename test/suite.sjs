var { test, context, assert } = require('sjs:test/suite');
var childProcess = require('sjs:nodejs/child-process');
var url = require('sjs:url');
var logging = require('sjs:logging');

var fixtures = url.normalize('fixtures/', module.id) .. url.toPath();
var fixture = (name) -> fixtures + name + '.js';

var error_output = function(text) {
	logging.info(text.stderr);
}

var run = function(cmd, args) {
	var result;
	try {
		result = childProcess.run(cmd, args, {stdio:'pipe'});
		result.code = 0;
	} catch(e) {
		result = e;
	}
	logging.info(result.stderr);
	return result;
}

context("nodejs minimal") {||
	test('write succeeds') {||
		var result = run('node', [fixture('minimal'), 'ok']);
		result.code .. assert.eq(0);
		result.stderr .. assert.eq("OK\n");
	}
	test('stat fails') {||
		var result = run('node', [fixture('minimal'), 'stat']);
		result.code .. assert.eq(null);
		result.signal .. assert.eq('SIGSYS');
		result.stderr .. assert.eq("START\n");
	}
}
