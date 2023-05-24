// Copyright (c)2023 Quinn Michaels
// Security Deva
// Security Deva Manages Security in deva.world.

const fs = require('fs');
const path = require('path');

const package = require('./package.json');
const info = {
  id: package.id,
  version: package.version,
  url: package.homepage,
  git: package.repository.url,
  bugs: package.bugs.url,
  author: package.author,
  license: package.license,
  copyright: package.copyright,
};

const data_path = path.join(__dirname, 'data.json');
const {agent,vars} = require(data_path).DATA;

const Deva = require('@indra.ai/deva');
const SECURITY = new Deva({
  info,
  agent: {
    id: agent.id,
    key: agent.key,
    prompt: agent.prompt,
    voice: agent.voice,
    profile: agent.profile,
    translate(input) {
      return input.trim();
    },
    parse(input) {
      return input.trim();
    }
  },
  vars,
  listeners: {},
  modules: {},
  deva: {},
  func: {
    sec_question(packet) {
      const agent = this.agent();
      const security = this.security();
      security.personal.answers.push(packet);
    },
    sec_answer(packet) {
      const agent = this.agent();
      const security = this.security();
      security.personal.answers.push(packet);
    },
  },
  methods: {
    /**************
    method: uid
    params: packet
    describe: Return a system id to the user from the :name:.
    ***************/
    uid(packet) {
      return Promise.resolve({text:this.uid()});
    },

    /**************
    method: status
    params: packet
    describe: Return the current status of the :name:.
    ***************/
    status(packet) {
      return this.status();
    },

    /**************
    method: help
    params: packet
    describe: The Help method returns the information on how to use the :name:.
    ***************/
    help(packet) {
      return new Promise((resolve, reject) => {
        this.lib.help(packet.q.text, __dirname).then(help => {
          return this.question(`#feecting parse ${help}`);
        }).then(parsed => {
          return resolve({
            text: parsed.a.text,
            html: parsed.a.html,
            data: parsed.a.data,
          });
        }).catch(reject);
      });
    }
  },
  onDone(data) {
    this.listen('devacore:question', packet => {
      const {text} = packet.q;
      if (text && text.includes(this.vars.trigger)) return this.func.sec_question(packet);
    });
    this.listen('devacore:answer', packet => {
      const {text} = packet.a;
      if (text &&  text.includes(this.vars.trigger)) return this.func.sec_answer(packet);
    });
    return Promise.resolve(data);
  }
});
module.exports = SECURITY
