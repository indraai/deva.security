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
    const uid = packet.q.text ? true : false
    this.feature('security');
    const id = this.lib.uid(uid);
    const data = [
      '',
      `::begin:uid:${id.uid}`,
      `uid: ${id.uid}`,
      `created: ${id.created}`,
      `md5: ${id.md5}`,
      `sha256: ${id.sha256}`,
      `sha512: ${id.sha512}`,
      `::end:uid:${id.uid}`,
    ].join('\n');
    return Promise.resolve(data);
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
  

  //TODO: build the write feature so it can write commands into the system.
  
}
