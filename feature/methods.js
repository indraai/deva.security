export default {

  /**************
  method: security
  params: packet
  describe: The global security feature that installs with every agent
  ***************/
  security(packet) {
    this.context('feature');
    return new Promise((resolve, reject) => {
      const security = this.security();
      const agent = this.agent();
      const global = [];
      security.global.forEach((item,index) => {
        global.push(`::begin:global:${item.key}:${item.id}`);
        for (let x in item) {
          global.push(`${x}: ${item[x]}`);
        }
        global.push(`::end:global:${item.key}:${this.lib.hash(item)}`);
      });
      const concerns = [];
      security.concerns.forEach((item, index) => {
        concerns.push(`${index + 1}. ${item}`);
      })
      
      const info = [
        '::BEGIN:SECURITY',
        '### Client',
        `::begin:client:${security.client_id}`,
        `id: ${security.client_id}`,
        `client: ${security.client_name}`,
        '**concerns**',
        concerns.join('\n'),
        `::end:client:${this.lib.hash(security)}`,
        '### Global',
        global.join('\n'),
        '::END:SECURITY'
      ].join('\n');
      this.question(`${this.askChr}feecting parse ${info}`).then(feecting => {
        return resolve({
          text: feecting.a.text,
          html: feecting.a.html,
          data: security.concerns,
        });
      }).catch(err => {
        return this.error(err, packet, reject);
      })
    });
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
    return Promise.resolve(id);
  },

  /**************
  method: md5 hash
  params: packet
  describe: Return system md5 hash for the based deva.
  ***************/
  hash(packet) {
    const transport = packet.id;
    this.feature('security');
    this.action('method', `hash:${transport}`);
    
    this.state('set', `meta:${transport}`); //set the meta state for the proxy
    const {meta} = packet.q; // set the meta information from the packet question.
    
    this.state('set', `params:${transport}`); //set the meta state for the proxy
    const {params} = meta; // set params from the meta information.
    
    this.state('set', `algo:${transport}`); //set the meta state for the proxy
    const algo = params[1] ? params[1] : 'md5'
    
    this.state('set', `hash:${transport}`); //set the meta state for the proxy
    const hash = this.lib.hash(packet.q.text, algo);
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
    this.feature('security');
    const theDate = this.lib.formatDate(Date.now(), 'long', true);
    return Promise.resolve(theDate);
  },
  /**************
  method: time
  params: packet
  describe: Return system date for today.
  ***************/
  time(packet) {
    this.feature('security');
    this.action('method', 'time')
    this.state('get', 'time')
    const theTime = Date.now();
    return Promise.resolve(theTime);
  },
  

  //TODO: build the write feature so it can write commands into the system.
  
}
