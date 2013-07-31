#!/usr/bin/env sjs
require('sjs:test/runner').run({
	base: module.id,
	modules: ['suite.sjs'],
});
