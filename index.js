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
    profile: agent.profile,
    translate(input) {
      return input.trim();
    },
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
    }
  },
  vars,
  listeners: {},
  modules: {},
  deva: {},
  func: {
    sec_question(packet) {return;},
    sec_answer(packet) {return;},
    async template(packet, route) {
      const agent = this.agent();
      const header = await this.question(this.vars.template.header.call);
      const footer = await this.question(this.vars.template.footer.call);
      const greeting = await this.question(this.vars.template.content.greeting);
      const signature = await this.question(this.vars.template.content.signature);
      const message = [
        greeting.a.text,
        '',
        packet.q.text,
        '',
        signature.a.text,
      ].join('\n');
      const header_parsed = this._agent.parse(header.a.text, route);
      const header_hash = this.hash(header_parsed);
      const footer_parsed = this._agent.parse(footer.a.text, route);
      const footer_hash = this.hash(footer_parsed);
      const message_parsed = this._agent.parse(message, route);
      const message_hash = this.hash(message_parsed)
      const template = [
        `${this.vars.template.header.begin}:${packet.id}`,
        header_parsed,
        `${this.vars.template.header.end}:${header_hash}`,
        '',
        `${this.vars.template.content.begin}:${packet.id}`,
        '',
        message_parsed,
        '',
        `${this.vars.template.content.end}:${message_hash}`,
        '',
        `${this.vars.template.footer.begin}:${packet.id}`,
        footer_parsed,
        `${this.vars.template.footer.end}:${this.hash(footer_hash)}`,
      ].join('\n');
      return template;
    },
    async chat(packet) {
      const param = packet.q.meta.params[1] || false;
      const local_route = param || this.vars.route;
      const route = this.config.routes[local_route];
      const question = await this.func.template(packet, route);
      let question_puppet = false;
      if (route.puppet_key) question_puppet = await this.func.template(packet, this.config.routes[route.puppet_key]);
      return new Promise((resolve, reject) => {
        if (!packet.q.text) return resolve(this._messages.notext);
        if (!param && route.puppet_key) this.question(`${route.puppet} ${question_puppet}`)
        this.question(`${route.call} ${question}`).then(answer => {
          return this.question(`#feecting parse ${answer.a.text}`);
        }).then(parsed => {
          return resolve({
            text: parsed.a.text,
            html: parsed.a.html,
            data: parsed.a.data,
          });
        }).catch(err => {
          return this.error(err, packet, reject);
        });
      });
    },
  },
  methods: {
    /**************
    func: chat
    params: packet
    describe: The chat relay interface to talk with the @api and @ui
    ***************/
    chat(packet) {
      return this.func.chat(packet);
    },

    /**************
    method: uid
    params: packet
    describe: Return a system id to the user from the :name:.
    ***************/
    uid(packet) {
      this.context('uid');
      return Promise.resolve({text:this.uid()});
    },

    /**************
    method: status
    params: packet
    describe: Return the current status of the :name:.
    ***************/
    status(packet) {
      this.context('status');
      return this.status();
    },

    /**************
    method: help
    params: packet
    describe: The Help method returns the information on how to use the :name:.
    ***************/
    help(packet) {
      this.context('help');
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
