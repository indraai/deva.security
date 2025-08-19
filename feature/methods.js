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
    this.feature('security');
    const hash = this.lib.hash(packet.q.text, 'md5');
    return Promise.resolve(hash);
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
  describe: Return current system hash time.
  ***************/
  async time(packet) {
    this.feature('security');
    const timestamp = Date.now();
    const created = this.lib.formatDate(Date.now(), 'long', true);
    
    const data = {
      packet,
      timestamp, 
      created,
    }
    data.md5 = this.lib.hash(data, 'md5');
    data.sha256 = this.lib.hash(data, 'sha256');
    data.sha512 = this.lib.hash(data, 'sha512');
    
    const feecting = await this.question(`${this.askChr}feecting parse ${text}`);
    return {
      text: feecting.a.text,
      html: feecting.a.html,
      data,
    }	  
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
  
  async sign(packet) {
    this.context('signature');
    this.action('method', 'signature');
    const uid = this.lib.uid(true);
    const transport = packet.id;
    
    const {meta} = packet.q;
    const {params} = meta;
    const opts = this.lib.copy(params);
    const cmd = opts.shift();

    const signer = !params[1] || params[1] === 'agent' ? this.agent() : this.client();
    const {profile} = signer;
        
    const timestamp = Date.now();
    const created = this.lib.formatDate(timestamp, 'long', true);
    const message = packet.q.text || '';
    const client = this.client();
    const agent = this.agent();
        
    const data = {
      uid,
      transport,
      opts: opts.join(' '),
      client: client.profile,
      agent: agent.profile,
      name: profile.name,
      computer: profile.computer,
      network: profile.network,
      caseid: profile.caseid,
      message,
      religion: profile.religion,
      created,
      timestamp,
      token: profile.token,
      copyright: profile.copyright,
    };
    data.md5 = this.lib.hash(data, 'md5');
    data.sha256 = this.lib.hash(data, 'sha256');
    data.sha512 = this.lib.hash(data, 'sha512');
    
    const text = [
      `uid: ${data.uid}`,
      `write ${data.opts}? if yes then write ${data.message}`,
      `::begin:signature:VectorGuardShield:${data.transport}`,
      `transport: ${data.transport}`,
      `caseid: ${data.caseid}`,
      `agent: ${agent.profile.id}`,
      `client: ${client.profile.id}`,
      `name: ${data.name}`,
      `religion: ${data.religion}`,
      `computer: ${data.computer}`,
      `network: ${data.network}`,
      `companies: ${JSON.stringify(data.companies)}`,
      `copyright: ${data.copyright}`,
      `created: ${data.created}`,
      `timestamp: ${data.timestamp}`,
      `md5: ${data.md5}`,
      `sha256: ${data.sha256}`,
      `sha512: ${data.sha512}`,
      `::end:signature:VectorGuardShield:${data.transport}`,
    ].join('\n').trim();
    const feecting = await this.question(`${this.askChr}feecting parse ${text}`);
    return {
      text: feecting.a.text,
      html: feecting.a.html,
      data,
    }	  
  },
}
