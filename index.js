// Copyright (c)2023 Quinn Michaels
// Security Deva
// Security Deva Manages Security in deva.world.
const fs = require('fs');
const path = require('path');
const package = require('./package.json');
const info = {
  id: package.id,
  name: package.name,
  describe: package.description,
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
    },
    process(input) {
      return input.trim();
    }
  },
  vars,
  listeners: {},
  modules: {},
  deva: {},
  func: {
    sec_question(packet) {return;},
    sec_answer(packet) {return;},
  },
  methods: {},
  onDone(data) {
    this.listen('devacore:question', this.func.sec_question);
    this.listen('devacore:answer', this.func.sec_answer);
    return Promise.resolve(data);
  }
});
module.exports = SECURITY
