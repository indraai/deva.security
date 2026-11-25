"use strict";
// Security Deva Test File
// Copyright ©2000-2026 Quinn Michaels; All rights reserved.  
// Owner Signature Required For Lawful Use.  
// Distributed under VLA:15266350905933520771 LICENSE.md
// Wednesday, November 25, 2026 - 9:44:25 AM PST

// run with: node --test
// MongoDB tests use a local server at mongodb://127.0.0.1:27017 by default. Set MONGO_URI to use another one.
// They skip with a message when MongoDB can't be reached.
import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {MongoClient} from 'mongodb';
import Deva from '@indra.ai/deva';
import core from '@indra.ai/deva/package.json' with {type:'json'};
import pkg from './package.json' with {type:'json'};
import featureMethods from './feature/methods.js';
import SECURITY from './index.js';

const DIR = dirname(fileURLToPath(import.meta.url));
const STAGES = ['start', 'enter', 'done', 'ready'];
const TIERS = ['md5', 'sha256', 'sha512'];
const PLACEHOLDER = /::[a-z-]+::|\{\{profile\.[a-z]+\}\}/;
const FEATURE_KEYS = ['uid', 'sign', 'hash', 'encrypt', 'decrypt', 'date', 'time'];

// test databases: the uri can change, the names are fixed so the after hook only ever drops the test databases.
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const SECURITY_DB = 'deva_security_test';
const SECURITY_LOG = 'deva_security_log_test';

// check the server once before the tests are defined so the MongoDB tests can skip cleanly.
const mongo = new MongoClient(MONGO_URI, {serverSelectionTimeoutMS: 2000});
const MONGO_SKIP = await mongo.db('admin').command({ping: 1}).then(
	() => false,
	err => `MongoDB is not reachable at ${MONGO_URI} (${err.message}). Start a local mongod or set MONGO_URI.`
);
if (MONGO_SKIP) console.log(`⏭️ ${MONGO_SKIP}`);

// stub client built in code: the core VLA for the core check, the agent VLA for Security Deva
// and the mongo settings for the security feature. useMongo false leaves the security feature without a database.
const client = (agentVLA = pkg.VLA, useMongo = true, uri = MONGO_URI, methods = false) => ({
	id: '00000000000000000000',
	key: 'client',
	VLA: structuredClone(core.VLA),
	prompt: {
		emoji: '🧪',
		text: 'client',
		colors: {
			label: {R: 2, G: 229, B: 77},
			text: {R: 2, G: 229, B: 77},
		},
	},
	profile: {
		id: '00000000000000000000',
		name: 'Test Client',
		describe: 'Test client for Security Deva',
		lang: 'en',
		locale: 'en-US',
		currency: 'USD',
	},
	features: {
		license: {
			concerns: [],
			global: [],
			devas: {
				security: structuredClone(agentVLA),
			},
		},
		security: {
			concerns: [],
			global: useMongo ? {mongo: {uri, database: SECURITY_DB, log: SECURITY_LOG}} : {},
			devas: useMongo ? {security: {mongo: {uri, database: SECURITY_DB, log: SECURITY_LOG}}} : {},
			methods: methods || undefined,
		},
	},
});

let securityClient = false; // Security Deva's own MongoClient, kept so the after hook can close it.

after(async () => {
	if (!MONGO_SKIP) {
		await mongo.db(SECURITY_DB).dropDatabase();
		await mongo.db(SECURITY_LOG).dropDatabase();
	}
	await mongo.close();
	if (securityClient) await securityClient.close();
});

test('security builds as a Deva and waits offline before init', async () => {
	assert.ok(SECURITY instanceof Deva, 'the export is a Deva');
	assert.equal(await SECURITY.stop(), SECURITY._messages.offline, 'stop before init answers offline');
});

test('security data has no placeholders left', () => {
	assert.doesNotMatch(JSON.stringify(pkg.data), PLACEHOLDER, 'package.json data');
	assert.doesNotMatch(JSON.stringify(pkg.VLA), PLACEHOLDER, 'package.json VLA');
	assert.doesNotMatch(pkg.copyright, PLACEHOLDER, 'package.json copyright');
});

test('func.write_log, onReady, onStop, and onError exist', () => {
	assert.equal(typeof SECURITY.func.write_log, 'function', 'func.write_log');
	assert.equal(typeof SECURITY.onReady, 'function', 'onReady');
	assert.equal(typeof SECURITY.onStop, 'function', 'onStop');
	assert.equal(typeof SECURITY.onError, 'function', 'onError');
});

test('security comes online and walks to ready', async () => {
	const prompts = [];
	SECURITY.listen('devacore:prompt', packet => prompts.push(packet.text));
	const data = await SECURITY.init(client());
	for (const k of STAGES) assert.equal(typeof data[k], 'number', `${k} timestamp`);
	assert.ok(data.start <= data.enter && data.enter <= data.done && data.done <= data.ready, 'stages in order');
	assert.equal(typeof data.id.uid, 'string', 'uid');
	for (const t of TIERS) assert.equal(typeof data[t], 'string', `${t} hash`);
	assert.ok(prompts.includes(`${SECURITY.vars.messages.ready} > VLA:${pkg.VLA.uid}`), 'onReady prompts the ready message');
	assert.ok(SECURITY.modules.client instanceof MongoClient, 'onReady builds the MongoClient');
	assert.equal(SECURITY.vars.database, SECURITY_DB, 'onReady sets the security database');
	assert.equal(SECURITY.vars.log, SECURITY_LOG, 'onReady sets the security log database');
	securityClient = SECURITY.modules.client;
});

test('security agent matches the package', () => {
	const agent = SECURITY.agent();
	assert.equal(agent.key, 'security');
	assert.equal(agent.id, pkg.id);
	assert.equal(agent.profile.id, pkg.id);
	assert.equal(agent.profile.name, 'Security Deva');
	assert.equal(agent.profile.owner, 'Quinn Michaels');
});

test('security utils answer with trimmed text', () => {
	const {translate, parse, process} = SECURITY.utils;
	for (const util of [translate, parse, process]) assert.equal(util('  hello  '), 'hello');
});

test('security help pages name the Deva and carry the package license', async () => {
	const main = await SECURITY.help('main', DIR);
	assert.match(main, /^# \{\{profile\.name\}\}$/m, 'main help heading');
	const license = await SECURITY.help('main:license', DIR);
	assert.match(license, new RegExp(`^uid: ${pkg.VLA.uid}$`, 'm'), 'license uid');
	for (const t of TIERS) assert.ok(license.includes(`${t}: ${pkg.VLA[t]}`), `${t} hash in the license help`);
});

// the feature loader binds client.features.security.methods onto the Deva at init.
// this uses a fresh instance so it does not change the methods on SECURITY.
test('feature methods from feature/methods.js load at runtime', async () => {
	assert.deepEqual(Object.keys(featureMethods), FEATURE_KEYS, 'feature export names');
	const {default: FEATURE} = await import('./index.js?feature');
	const data = await FEATURE.init(client(pkg.VLA, false, MONGO_URI, featureMethods));
	assert.equal(typeof data.ready, 'number', 'feature instance reaches ready');
	for (const key of FEATURE_KEYS) assert.equal(typeof FEATURE.methods[key], 'function', `methods.${key}`);
	await FEATURE.stop();
});

// onReady must read this.security().global?.mongo, not this.report() or this.legal().
test('onReady reads mongo from this.security() not another Deva', async () => {
	const {default: CONFIG} = await import('./index.js?config');
	const c = client();
	c.features.report = {
		concerns: [],
		global: {mongo: {uri: MONGO_URI, database: 'WRONG_REPORT_DB', log: 'WRONG_REPORT_LOG'}},
		devas: {},
	};
	c.features.legal = {
		concerns: [],
		global: {mongo: {uri: MONGO_URI, database: 'WRONG_LEGAL_DB', log: 'WRONG_LEGAL_LOG'}},
		devas: {},
	};
	const data = await CONFIG.init(c);
	assert.equal(typeof data.ready, 'number', 'config instance reaches ready');
	assert.equal(CONFIG.vars.database, SECURITY_DB, 'database comes from this.security()');
	assert.equal(CONFIG.vars.log, SECURITY_LOG, 'log comes from this.security()');
	assert.notEqual(CONFIG.vars.database, 'WRONG_REPORT_DB');
	assert.notEqual(CONFIG.vars.database, 'WRONG_LEGAL_DB');
	await CONFIG.stop();
});

// onReady builds a MongoClient but does not connect, so an unreachable uri still reaches ready.
test('init with an unreachable MongoDB uri still reaches ready', async () => {
	const {default: UNREACH} = await import('./index.js?unreachable');
	const bad = 'mongodb://127.0.0.1:1';
	const data = await UNREACH.init(client(pkg.VLA, true, bad));
	assert.equal(typeof data.ready, 'number', 'unreachable uri still reaches ready');
	assert.ok(UNREACH.modules.client instanceof MongoClient, 'onReady still builds the MongoClient');
	assert.equal(UNREACH.vars.database, SECURITY_DB);
	assert.equal(UNREACH.vars.log, SECURITY_LOG);
	await UNREACH.stop();
});

test('write_log inserts a document into the finish collection', {skip: MONGO_SKIP}, async () => {
	const payload = {id: {uid: 'write-log-test-1'}, content: 'hello security', created: Date.now()};
	const ans = await SECURITY.func.write_log('finish', payload);
	assert.equal(ans.acknowledged, true);
	const doc = await mongo.db(SECURITY_LOG).collection('finish').findOne({'id.uid': 'write-log-test-1'});
	assert.equal(doc?.content, 'hello security');
});

// runs in a child process with a fresh Security Deva and no database, so it does not
// share the bound func object or MongoClient with the tests that use SECURITY.
// with no MongoDB client, write_log returns quietly with undefined and does not throw or hang.
test('write_log returns quietly when no MongoDB client is built', async () => {
	const code = [
		`const {default: SECURITY} = await import(${JSON.stringify(new URL('./index.js', import.meta.url).href)});`,
		'await SECURITY.init(JSON.parse(process.env.SECURITY_TEST_CLIENT));',
		"const payload = {id: {uid: 'write-log-missing-1'}, content: 'no mongo'};",
		'let timer;',
		'const ans = await Promise.race([',
		'	SECURITY.func.write_log("finish", payload),',
		'	new Promise((_, reject) => {timer = setTimeout(() => reject(new Error("TIMEOUT")), 8000);}),',
		']).finally(() => clearTimeout(timer));',
		'console.log(`ANSWER:${typeof ans}`);',
		'await SECURITY.stop();',
		'console.log("RESULT:ok");',
	].join('\n');
	const env = {PATH: process.env.PATH, SECURITY_TEST_CLIENT: JSON.stringify(client(pkg.VLA, false))};
	const run = promisify(execFile)(process.execPath, ['--input-type=module', '-e', code], {cwd: DIR, env, timeout: 20000, killSignal: 'SIGKILL'});
	const {stdout} = await run.catch(err => {
		if (err.stdout) assert.fail(err.stdout.trim());
		const why = err.killed ? 'did not return within 20 seconds' : `failed: ${err.message}`;
		assert.fail(`write_log without a MongoDB client ${why}`);
	});
	assert.match(stdout, /^ANSWER:undefined$/m, 'write_log returns undefined without a client');
	assert.match(stdout, /^RESULT:ok$/m, 'write_log returned without hanging');
});

test('a stop and init restart builds a new MongoClient and can write_log again', {skip: MONGO_SKIP}, async () => {
	const before = SECURITY.modules.client;
	await SECURITY.stop();
	const data = await SECURITY.init(client());
	assert.equal(typeof data.ready, 'number', 'restart reaches ready');
	assert.ok(SECURITY.modules.client instanceof MongoClient, 'restart builds a MongoClient');
	assert.notEqual(SECURITY.modules.client, before, 'the MongoClient is new');
	securityClient = SECURITY.modules.client;
	const payload = {id: {uid: 'write-log-restart-1'}, content: 'after restart', created: Date.now()};
	const ans = await SECURITY.func.write_log('complete', payload);
	assert.equal(ans.acknowledged, true);
	const doc = await mongo.db(SECURITY_LOG).collection('complete').findOne({'id.uid': 'write-log-restart-1'});
	assert.equal(doc?.content, 'after restart');
});

test('security stops through the full chain', async () => {
	const data = await SECURITY.stop();
	assert.equal(data.key, 'shutdown', 'the chain ends on shutdown');
	assert.equal(data.value, 'security');
	securityClient = false;
});

// the refusal check loads a fresh Security Deva instance from the same file, so it starts from a clean state.
test('security refuses to start with a bad agent VLA', async () => {
	const {default: REFUSE} = await import('./index.js?refuse');
	const prompts = [];
	REFUSE.listen('devacore:prompt', packet => prompts.push(packet.text));
	const result = await REFUSE.init(client({uid: 'bad'}));
	assert.equal(result, REFUSE._messages.checkVLA, 'init answers with the invalid VLA message');
	assert.ok(prompts.includes(REFUSE._messages.checkVLA), 'core prompts the invalid VLA message');
	assert.equal(REFUSE._active, false, 'the Deva stays offline');
	if (REFUSE.modules?.client) await REFUSE.modules.client.close();
});
