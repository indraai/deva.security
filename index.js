"use strict"
// Security Deva
// Copyright ©2000-2026 Quinn Michaels; All rights reserved. 
// Owner Signature Required For Lawful Use.
// Distributed under VLA:15266350905933520771 LICENSE.md
// Wednesday, November 25, 2026 - 9:44:25 AM PST

import Deva from '@indra.ai/deva';
import { MongoClient } from 'mongodb';

import pkg from './package.json' with {type:'json'};
const {agent,vars} = pkg.data;

// set the __dirname
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';    
const __dirname = dirname(fileURLToPath(import.meta.url));

const info = {
	id: pkg.id,
	name: pkg.name,
	describe: pkg.description,
	version: pkg.version,
	url: pkg.homepage,
	dir: __dirname,
	git: pkg.repository.url,
	bugs: pkg.bugs.url,
	author: pkg.author,
	license: pkg.license,
	VLA: pkg.VLA,
	copyright: pkg.copyright,
};

const SecurityDeva = new Deva({
	info,
	agent,
	vars,
	utils: {
		translate(input) {return input.trim();},
		parse(input) {return input.trim();},
		process(input) {return input.trim();}
	},
	listeners: {
		// log the answer on finish
		'devacore:finish'(packet) {
			if (!this._active) return;
			this.func.write_log('finish', this.lib.copy(packet));
		},
		// log the answer on complete
		'devacore:complete'(packet) {
			if (!this._active) return;
			this.func.write_log('complete', this.lib.copy(packet));
		},
	},
	modules: {},
	devas: {},
	func: {
		/**************
		func: write_log
		params: type, packet
		describe: this is the log file writer function that handles 
		writing for finish and complete for complete chain of custody.
		***************/
		async write_log(type, packet) {
			let result = false;
			if (!this.modules.client) return;        
			try {
				const database = this.modules.client.db(this.vars.log);
				const collection = database.collection(type);
				result = await collection.insertOne(packet);
				return result;
			} 
			catch (err) {
				return this.err(err, packet);
			}
		},
		
	},
	methods: {},  
	onReady(data, resolve) {
		const {VLA} = this.info();
		const {uri, database, log} = this.security().global?.mongo || {};
		if (database) this.vars.database = database; // set the main database
		if (log) this.vars.log = log; // set the logging database
		if (uri) this.modules.client = new MongoClient(uri); // build the client if uri is set
		this.prompt(`${this.vars.messages.ready} > VLA:${VLA.uid}`);
		return resolve(data);
	},
	onStop(data, resolve) {
		const {client} = this.modules;
		if (!client) return this.close(data, resolve);
		return client.close().then(() => this.close(data, resolve)); // close the database before shutdown
	},
	onError(err, data, reject) {
		this.prompt(this.vars.messages.error);
		console.error(err);
		return reject ? reject(err) : Promise.reject(err);
	}
});
export default SecurityDeva
