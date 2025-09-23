"use strict"
// Copyright ©2025 Quinn A Michaels; All rights reserved. 
// Legal Signature Required For Lawful Use.
// Distributed under VLA:45249771785697968797 LICENSE.md
// Security Deva

import Deva from '@indra.ai/deva';
import { MongoClient, ObjectId } from 'mongodb';

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

const SECURITY = new Deva({
  info,
  agent,
  vars,
  utils: {
    translate(input) {return input.trim();},
    parse(input, route=false) {
      // with the parse method we are going to take the input with a
      // values object to provide the personalization
      let output = input;
      if (route) for (let x in route) {
        const key = `::${x}::`;
        const value = route[x];
        output = output.replace(key, value);
      }
      return output.trim();
    },
    process(input) {return input.trim();}
  },
  listeners: {
    // log the answer on complete
    'devacore:complete'(packet) {
      this.func.write_log('complete', packet);
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
      try {
        const database = this.modules.client.db(this.vars.log);
        const collection = database.collection(type);
        result = await collection.insertOne(packet);
      } catch (e) {
        return this.err(e, packet, false);
      } finally {
        return result;
      }
    },
    
  },
  methods: {},
  onInit(data, resolve) {
    const {personal} = this.license(); // get the license config
    const agent_license = this.info().VLA; // get agent license
    const license_check = this.license_check(personal, agent_license); // check license
    // return this.start if license_check passes otherwise stop.
    this.action('return', `onInit:${data.id.uid}`);
    return license_check ? this.start(data, resolve) : this.stop(data, resolve);
  }, 
  onReady(data, resolve) {
    const {VLA} = this.info();

    this.state('get', `mongo:global:${data.id.uid}`);
    const {uri,database, log} = this.security().global.mongo;
    this.state('set', `mongo:client:${data.id.uid}`);
    this.modules.client = new MongoClient(uri);
    this.state('set', `mongo:database:${data.id.uid}`);
    this.vars.database = database;
    this.state('set', `mongo:log:${data.id.uid}`);
    this.vars.log = log;

    this.prompt(`${this.vars.messages.ready} > VLA:${VLA.uid}`);
    
    this.action('resolve', `onReady:${data.id.uid}`);
    return resolve(data);
  },
  onError(err, data, reject) {
    this.prompt(this.vars.messages.error);
    console.log(err);
    return reject(err);
  }
});
export default SECURITY
