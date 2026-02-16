"use strict";
// Security Deva Feature Methods
// Copyright ©2000-2026 Quinn A Michaels; All rights reserved. 
// Legal Signature Required For Lawful Use.
// Distributed under VLA:72981472549283584069 LICENSE.md
// Sunday, January 11, 2026 - 7:42:24 AM

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
  async uid(packet) {
    return new Promise((resolve, reject) => {
      const uuid = packet.q.text ? true : false
      const id = this.uid(uuid);
      this.context('uid', packet.id.uid);
      this.feature('security', `uid:${id.uid}`);
      this.zone('security', `uid:${id.uid}`);
      this.belief('security', `uid:${id.uid}`)
      const {key,profile,prompt} = this.agent();
                      
      const showJSON = packet.q.meta.params[1] || false;
      const status = `${key}:uid:${id.uid}`;

      const text = [
        `${this.box.begin}:${status}`,
        `uid: ${id.uid}`,
        `time: ${id.time}`,
        `iso: ${id.iso}`,
        `utc: ${id.utc}`,
        `date: ${id.date}`,
        `warning: ${id.warning}`,
        `license: ${id.license}`,
        `fingerprint: ${id.fingerprint}`,
        `copyright: ${id.copyright}`,
        `${this.box.end}:${status}`,
      ];
      const data = {
        uid:  id.uid,
        time: id.time,
        date: id.date,
        warning: id.warning,
        license: id.license,
        fingerprint: id.fingerprint,
        copyright: id.copyright,
      }
      if (showJSON) {
        text.push(`${this.box.begin}${key}:uid:json:${data.uid}`);
        text.push(JSON.stringify(data, null, 2)); 
        text.push(`${this.box.end}${key}:uid:json:${data.uid}`);
      }
      
      this.question(`${this.askChr}feecting parse ${text.join('\n')}`, {vars:this.vars}).then(parsed => {
        this.belief('vedic', `uid:${packet.id.uid}`);
        this.action('resolve', `uid:${packet.id.uid}`);
        return resolve({
          text: parsed.a.text,
          html: parsed.a.html,
          data,
        });        
      }).catch(err => {
        return this.err(err, packet, reject);
      });
    });
  },

  async sign(packet) {
    const data = this.sign(packet);    
    
    // Text data that is joined by line breaks and then trimmed.
    this.state('set', `${data.key}:${data.method}:text:${data.id.uid}`); // set state to text for output formatting.
    const text = [
      `write: #${data.key}.${data.method}.${data.opts} ${data.text}`,
      '\n',
      `${this.box.begin}${data.method}:${data.id.uid}`,
      `sign: ${data.client.fullname} ${data.client.emojis}`,
      `uid: ${data.id.uid}`,
      `time: ${data.time}`,
      `expires: ${data.client.expires}`,
      `fingerprint: ${data.id.fingerprint}`,
      `name: ${data.client.name}`,
      `fullname: ${data.client.fullname}`,
      `company: ${data.client.company}`,
      `caseid: ${data.client.caseid}`,
      `agent: ${data.agent.sha256}`,
      `token: ${data.client.token}`,
      `warning: ${data.warning}`,
      `created: ${data.created}`,
      `copyright: ${data.copyright}`,
      `md5: ${data.md5}`,
      `sha256: ${data.sha256}`,
      `sha512: ${data.sha512}`,
      `${this.box.end}${data.method}:${data.id.uid}`,
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

  /**************
  method: md5, sha256, sha512 hash
  params: packet
  describe: Return system md5, sha256, sha512 hash from value.
  ***************/
  async hash(packet) {
    const id = this.uid();
    const {q} = packet;
    this.feature('security', `hash:${id.uid}`);
    const {global, personal} = this.security();
    const agent = this.agent()
    const client = this.client();
    
    this.zone('security', `hash:${id.uid}`);
    this.action('method', `hash:${id.uid}`);

    const {params} = q.meta; // set params from the meta information.

    this.state('set', `hash:algo:${id.uid}`); //set the meta state for the proxy
    const algo = params[1] || personal.hash || global.hash
    
    this.state('set', `hash:${id.uid}`); //set the meta state for the proxy
    const hash = this.hash(q.text, algo);
    
    const data = {
      id,
      algo,
      text: q.text,
      hash,
    };

    const status = `${agent.key}:hash:${data.id.uid}`;
    
    const text = [
      `${this.box.begin}:${status}`,
      `uid: ${data.id.uid}`,
      `algo: ${data.algo}`,
      `text: ${data.text}`,
      `hash: ${data.hash}`,
      `time: ${data.id.time}`,
      `date: ${data.id.date}`,
      `warning: ${data.id.warning}`,
      `license: ${data.id.license}`,
      `copyright: ${data.id.copyright}`,
      `${this.box.end}:${status}`,
    ].join('\n');

    this.action('return', `hash:${data.id.uid}`);
    this.state('valid', `hash:${data.id.uid}`);
    this.intent('good', `hash:${data.id.uid}`);
    return {
      text, 
      html: false,
      data,
    };
  },

  /**************
  method: encrypt
  params: packet
  describe: Return system md5 hash for the based deva.
  ***************/
  async encrypt(packet) {
    const id = this.uid();
    const {q} = packet;
    this.feature('security', `encrypt:${id.uid}`);
    const {global,personal} = this.security();
    const agent = this.agent();
    this.zone('security', `encrypt:${id.uid}`);
    this.action('encrypt', id.uid);

    this.state('set', `encrypt:data:${id.uid}`); // set state data
    const data = this.lib.encrypt(q.text, global.encrypt);
    data.id = id;
    
    this.action('hash', `encrypt:data:md5:${id.uid}`); // set action hash
    data.md5 = this.hash(data.encrypted, 'md5');
    this.action('hash', `encrypt:data:sha256:${id.uid}`); // set action hash
    data.sha256 = this.hash(data.encrypted, 'sha256');
    this.action('hash', `encrypt:data:sha512:${id.uid}`); // set action hash
    data.sha512 = this.hash(data.encrypted, 'sha512');

    const status = `${agent.key}:encrypt:${id.uid}`;
    
    this.state('set', `encrypt:text:${id.uid}`)
    const text = [
      `${this.box.begin}:${status}`,
      `uid: ${id.uid}`,
      `text: ${q.text}`,
      `iv: ${data.iv}`,
      `key: ${data.key}`,
      `encrypted: ${data.encrypted}`,
      `time: ${id.time}`,
      `date: ${id.date}`,
      `warning: ${id.warning}`,
      `copyright: ${id.copyright}`,
      `md5: ${data.md5}`,
      `sha256: ${data.sha256}`,
      `sha512: ${data.sha512}`,
      `${this.box.end}:${status}`,
    ].join('\n');
    
    this.action('return', `encrypt:${id.uid}`); // set action return
    this.state('valid', `encrypt:${id.uid}`); // set action return
    this.intent('good', `encrypt:${id.uid}`); // set action return
    return {
      text,
      html: false,
      data,
    };
  },

  async decrypt(packet) {
    const id = this.uid();
    const {q} = packet
    this.feature('security', `decrypt:${id.uid}`);
    this.zone('security', `decrypt:${id.uid}`);
    const {global,personal} = this.security();

    this.state('set', `decrypt:agent:${id.uid}`); // set state set
    const agent = this.agent();
    this.state('set', `decrypt:client:${id.uid}`); // set state set
    const client = this.client();

    this.state('set', `decrypt:encrypt:${id.uid}`); // set state set
    const encrypt = {
      iv: q.meta.params[1],
      key: q.meta.params[2],
      encrypted: q.text,
      algorithm: global.encrypt.algorithm,
    }
    
    this.action('decrypt', id.uid); // set action hash
    const decrypt = this.lib.decrypt(encrypt);
    
    this.state('set', `decrypt:data:${id.uid}`); // set state set
    const data = {
      id,
      agent,
      decrypt,
      encrypt,
    };

    this.action('hash', `decrypt:data:md5:${id.uid}`); // set action hash
    data.md5 = this.hash(decrypt, 'md5');
    this.action('hash', `decrypt:data:sha256:${id.uid}`); // set action hash
    data.sha256 = this.hash(decrypt, 'sha256');
    this.action('hash', `decrypt:data:sha512:${id.uid}`); // set action hash
    data.sha512 = this.hash(decrypt, 'sha512');
    
    const status = `${agent.key}:decrypt:${data.id.uid}`;
    
    this.state('set', `decrypt:text:${id.uid}`); // set state set
    const text = [
      `${this.box.begin}:${status}`,
      `uid: ${data.id.uid}`,
      `decrypted: ${data.decrypt}`,
      `time: ${data.id.time}`,
      `date: ${data.id.date}`,
      `warning: ${data.id.warning}`,
      `copyright: ${data.id.copyright}`,
      `md5: ${data.md5}`,
      `sha256: ${data.sha256}`,
      `sha512: ${data.sha512}`,
      `${this.box.end}${status}`,
    ].join('\n');
    

    this.action('return', `decrypt:${id.uid}`); // set action return
    this.state('valid', `decrypt:${id.uid}`); // set action return
    this.intent('good', `decrypt:${id.uid}`); // set action return
    return {
      text,
      html: false,
      data,
    };
  },
   
  /**************
  method: date
  params: packet
  describe: Return system date for today.
  ***************/
  async date(packet) {
    return new Promise((resolve, reject) => {
      const id = this.uid();
      const time = Date.now();
      const {params} = packet.q.meta;
      const {key} = this.agent();
      this.zone('security', `date:${id.uid}`);
      this.feature('security', `date:${id.uid}`);
      this.action('method', `date:${id.uid}`);
      
      this.state('set', `date:setFormat:${id.uid}`); // set state set
      const setFormat = params[1] ? params[1] : 'long';
      this.state('set', `date:setTime:${id.uid}`); // set state set
      const setTime = params[2] ? packet.q.meta.params[2] : false;
      
      this.state('set', `date:${id.uid}`);
      const date = this.lib.formatDate(time, setFormat, setTime);
      
      const data = {
        id,
        time,
        date,
      }
  
      this.action('hash', `date:data:md5:${id.uid}`); // set action hash
      data.md5 = this.hash(date, 'md5');
      this.action('hash', `date:data:sha256:${id.uid}`); // set action hash
      data.sha256 = this.hash(date, 'sha256');
      this.action('hash', `date:data:sha512:${id.uid}`); // set action hash
      data.sha512 = this.hash(date, 'sha512');
  
      const text = [
        `${this.box.begin}:${key}:date:${data.id.uid}`,
        `uid: ${data.id.uid}`,
        `time: ${data.time}`,
        `date: ${data.date}`,
        `copyright: ${data.id.copyright}`,
        `md5: ${data.md5}`,
        `sha256: ${data.sha256}`,
        `sha512: ${data.sha512}`,
        `${this.box.end}:${key}:date:${data.id.uid}`
      ].join('\n');
      
      this.question(`${this.askChr}feecting parse ${text}`).then(feecting => {
        data.feecting = feecting;
        this.action('return', `date:${id.uid}`);
        this.state('valid', `date:${id.uid}`);
        this.intent('good', `date:${id.uid}`);
        return resolve({
          text: feecting.a.text,
          html: feecting.a.html,
          data,
        });        
      }).catch(err => {
        return reject(err, data, reject);
      })

    });    
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
  
}
