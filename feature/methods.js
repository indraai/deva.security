"use strict";
// ©2025 Quinn A Michaels; All rights reserved. 
// Legal Signature Required For Lawful Use.
// Distributed under VLA:36687315706419437672 LICENSE.md

export default {

  /**************
  method: security
  params: packet
  describe: The global security feature that installs with every agent
  ***************/
  async security(packet) {
    const security = await this.methods.sign('security', 'default', packet);
    return security;
  },

  /**************
  method: uid
  params: packet
  describe: Return a system id to the user from the Log Buddy.
  ***************/
  uid(packet) {
    this.feature('security', `uid:${packet.id.uid}`);
    this.zone('security', `uid:${packet.id.uid}`);
    const agent = this.agent();
    const {key} = agent;

    const uuid = packet.q.text ? true : false
    const id = this.uid(uuid);

    const {client} = packet.q;
        
    const text = [
      '→',
      '::::',
      `::begin:uid:${key}:${id.uid}`,
      `uid: ${id.uid}`,
      `time: ${id.time}`,
      `date: ${id.date}`,
      `client: ${id.client}`,
      `agent: ${id.agent}`,
      `pkg: ${id.pkg}`,
      `machine: ${id.machine}`,
      `warning: ${id.warning}`,
      `copyright: ${id.copyright}`,
      `md5: ${id.md5}`,
      `sha256: ${id.sha256}`,
      `sha512: ${id.sha512}`,
      `::end:uid:${key}:${id.uid}`,
      '::::',
    ].join('\n');
    return Promise.resolve({
      text,
      html: false,
      data: id,
    });
  },

  /**************
  method: md5, sha256, sha512 hash
  params: packet
  describe: Return system md5, sha256, sha512 hash from value.
  ***************/
  hash(packet) {
    const transport = packet.id;
    this.zone('security', `hash:${transport}`);
    this.feature('security', `hash:${transport}`);
    this.action('method', `hash:${transport}`);
    
    this.state('set', `meta:${transport}`); //set the meta state for the proxy
    const {meta} = packet.q; // set the meta information from the packet question.
    
    this.state('set', `params:${transport}`); //set the meta state for the proxy
    const {params} = meta; // set params from the meta information.
    
    this.state('set', `algo:${transport}`); //set the meta state for the proxy
    const algo = params[1] ? params[1] : 'md5'
    
    this.state('set', `hash:${transport}`); //set the meta state for the proxy
    const hash = this.lib.hash(packet.q.text, algo);
    
    this.state('return', `hash:${transport}`);
    return Promise.resolve(hash);
  },

  /**************
  method: md5 cipher
  params: packet
  describe: Return system md5 hash for the based deva.
  ***************/
  cipher(packet) {
    this.feature('security');
    const data = this.lib.cipher(packet.q.text);
    const cipher = `cipher: ${data.encrypted}`;
    return Promise.resolve(cipher);
  },
  
  /**************
  method: today
  params: packet
  describe: Return system date for today.
  ***************/
  today(packet) {
    const transport = packet.id;
    this.zone('security', `today:${transport}`);
    this.feature('security', `today:${transport}`);
    this.action('method', `today:${transport}`);
    this.state('get', `today:${transport}`);
    const theDate = this.lib.formatDate(Date.now(), 'long', true);
    this.state('get', `today:${transport}`);
    return Promise.resolve(theDate);
  },
  /**************
  method: time
  params: packet
  describe: Return system date for today.
  ***************/
  time(packet) {
    const transport = packet.id;
    this.zone('security', `time:${transport}`);
    this.feature('security', `time:${transport}`);
    this.action('method', `time:${transport}`);
    this.state('get', `time:${transport}`);
    const theTime = Date.now();
    this.state('return', `time:${transport}`);
    return Promise.resolve(theTime);
  },
  

  async sign(packet) {
    const data = this.sign(packet);    
    
    // Text data that is joined by line breaks and then trimmed.
    this.state('set', `${data.key}:${data.method}:text:${data.id.uid}`); // set state to text for output formatting.
    const text = [
      '→',
      `::BEGIN:${data.container}`,
      `#${data.key}.${data.method}.${data.opts} ${data.text}`,
      '\n---\n',
      `sign:${data.client.fullname}${data.client.emojis}`,
      '\n',
      `::begin:${data.method}:${data.key}:${data.id.uid}`,
      `transport: ${data.id.uid}`,
      `time: ${data.time}`,
      `expires: ${data.client.expires}`,
      `name: ${data.client.name}`,
      `fullname: ${data.client.fullname}`,
      `company: ${data.client.company}`,
      `caseid: ${data.client.caseid}`,
      `client: ${data.client.sha256}`,
      `agent: ${data.agent.sha256}`,
      `token: ${data.client.token}`,
      `warning: ${data.warning}`,
      `created: ${data.created}`,
      `copyright: ${data.copyright}`,
      `md5: ${data.md5}`,
      `sha256: ${data.sha256}`,
      `sha512: ${data.sha512}`,
      `::end:${data.method}:${data.key}:${data.id.uid}`,
      `::END:${data.container}`,
    ].join('\n').trim();
    
    // send the text data to #feecting to parse and return valid text, html, and data.
    this.action('parse', `${data.key}:${data.method}:parse:${data.id.uid}`); // action set to feecting parse 
    const feecting = await this.question(`${this.askChr}feecting parse:${data.id.uid} ${text}`); // parse with feecting agent.
    
    this.action('return', `${data.key}:${data.method}:${data.id.uid}`); // set the state to return proxy
    return {
      text: feecting.a.text,
      html: feecting.a.html,
      data,
    }	  
    
  },
  
}
