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
    const {key} = this.agent();
    
    const data = [
      '',
      `::begin:uid:${key}:${id.uid}`,
      `uid: ${id.uid}`,
      `created: ${id.created}`,
      `md5: ${id.md5}`,
      `sha256: ${id.sha256}`,
      `sha512: ${id.sha512}`,
      `::end:uid:${key}:${id.uid}`,
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
  

  async sign(key, type, packet) {
    this.state('set', `${key}:sign:${type}:${packet.id.uid}`);
    const transport = packet.id; // set the transport id from the packet id.
  
    this.zone(key, `${key}:sign:${type}:${transport.uid}`); // set the zone
    this.feature(key, `${key}:sign:${type}:${transport.uid}`); // set the feature
    this.context(key, `${key}:sign:${type}:${transport.uid}`); // set the agent context to proxy.
    this.action('method', `${key}:sign:${type}:${transport.uid}`); // set the action method to proxy.
    
    this.state('set', `${key}:sign:${type}:uid:${transport.uid}`); //set the uid state
    const id = this.lib.uid(true); // The UID
    
    this.state('set', `${key}:sign:${type}:time:${transport.uid}`); //set the time state
    const time = Date.now(); // current timestamp
    
    this.state('created', `${key}:sign:${type}:created:${transport.uid}`); //set the created state
    const created = this.lib.formatDate(time, 'long', true); // Formatted created date.
    
    this.state('set', `${key}:sign:${type}:concerns:${transport.uid}`); //set the concerns
    const {concerns} = this[key](); // load the Guard profile
    
    this.state('set', `${key}:sign:${type}:agent:${transport.uid}`); //set the agent state
    const agent = this.agent(); // the agent processing the proxy
  
    this.state('set', `${key}:sign:${type}:client:${transport.uid}`); //set the client state
    const client = this.client(); // the client requesting the proxy
  
    this.state('set', `${key}:sign:${type}:expires:${transport.uid}`); //set the time state
    const expires = time + (client.expires || agent.expires || 10000); // signature expires in milliseconds
    
    this.state('set', `${key}:sign:${type}:meta:${transport.uid}`); //set the meta state
    const {meta} = packet.q; // set the meta information from the packet question.
    
    this.state('set', `${key}:sign:${type}:params:${transport.uid}`); //set the meta state
    const {params} = meta; // set params from the meta information.
    
    this.state('set', `${key}:sign:${type}:opts:${transport.uid}`); //set the opts state
    const opts = this.lib.copy(params); // copy the params and set as opts.
    
    this.state('set', `${key}:sign:${type}:command:${transport.uid}`); //set the opts state
    const command = opts.shift(); // extract the command first array item out of opts.
    
    this.state('set', `${key}:sign:${type}:message:${transport.uid}`); //set the message state
    const message = packet.q.text; // set packet.q.text as the message of the proxy.
    
    this.state('set', `${key}:sign:${type}:container:${transport.uid}`); //set the message state
    const container = `OM:${key.toUpperCase()}:${transport.uid}`; // set container string.
  
    this.state('set', `${key}:sign:${type}:write:${transport.uid}`); //set the message state
    const write = client.profile.write; // set write string.
    
    // hash the agent profile for security
    this.state('hash', `${key}:sign:${type}:packet:sha256:${transport.uid}`);
    const packet_hash = this.lib.hash(packet, 'sha256');
  
    // hash the agent profile for security
    this.state('hash', `${key}:sign:${type}:agent:sha256:${transport.uid}`);
    const agent_hash = this.lib.hash(agent, 'sha256');
    
    // hash the agent profile for security
    this.state('hash', `${key}:sign:${type}:client:sha256:${transport.uid}`);
    const client_hash = this.lib.hash(client, 'sha256');
  
    // hash the agent profile for security
    this.state('hash', `${key}:sign:${type}:laws:sha256:${transport.uid}`);
    const laws_hash = this.lib.hash(agent.laws || client.laws, 'sha256');
    
    // hash the agent profile for security
    this.state('hash', `${key}:sign:${type}:token:${transport.uid}`);
    const token = this.lib.hash(`${key} client:${client.profile.id} fullname:${client.profile.fullname} transport:${transport.uid}`, 'sha256');
  
    
    this.state('set', `${key}:sign:${type}:write:${transport.uid}`); // set the state to set data 
    // data packet
    const data = {
      id,
      transport,
      time,
      expires,
      container,
      write,
      message,
      caseid: client.profile.caseid,
      opts: opts.length? `.${opts.join('.')}` : '',
      name: client.profile.name,
      fullname: client.profile.fullname,
      emojis: client.profile.emojis,
      company: client.profile.company,
      client: client_hash,
      agent: agent_hash,
      packet: packet_hash,
      laws: laws_hash,
      warning: agent.warning || client.warning || 'none',
      token,
      concerns,
      meta,
      params,
      command,
      created,
      copyright: client.profile.copyright,
    };
    
    this.state('hash', `${key}:sign:${type}:md5:${transport.uid}`); // set state to secure hashing
    data.md5 = this.lib.hash(data, 'md5'); // hash data packet into md5 and inert into data.
    
    this.state('hash', `${key}:sign:${type}:sha256:${transport.uid}`); // set state to secure hashing
    data.sha256 = this.lib.hash(data, 'sha256'); // hash data into sha 256 then set in data.
    
    this.state('hash', `${key}:sign:${type}:sha512:${transport.uid}`); // set state to secure hashing
    data.sha512 = this.lib.hash(data, 'sha512'); // hash data into sha 512 then set in data.
    
    // Text data that is joined by line breaks and then trimmed.
    this.state('set', `${key}:sign:${type}:text:${transport.uid}`); // set state to text for output formatting.
    const text = [
      `::::`,
      `::BEGIN:${data.container}`,
      `#${key}.${type}${data.opts} ${write}? if true ${write} ${data.message}`,
      '\n---\n',
      'Signed',
      data.fullname,
      data.emojis,
      '\n',
      `::begin:${key}:${type}:${transport.uid}`,
      `transport: ${data.transport.uid}`,
      `time: ${data.time}`,
      `expires: ${data.expires}`,
      `name: ${data.name}`,
      `fullname: ${data.fullname}`,
      `company: ${data.company}`,
      `caseid: ${data.caseid}`,
      `agent: ${data.agent}`,
      `client: ${data.client}`,
      `packet: ${data.packet}`,
      `token: ${data.token}`,
      `laws: ${data.laws}`,
      `warning: ${data.warning}`,
      `created: ${data.created}`,
      `copyright: ${data.copyright}`,
      `md5: ${data.md5}`,
      `sha256: ${data.sha256}`,
      `sha512: ${data.sha512}`,
      `::end:${key}:${type}${data.transport.uid}`,
      `::END:${data.container}`,
      `::::`
    ].join('\n').trim();
    
    // send the text data to #feecting to parse and return valid text, html, and data.
    this.action('question', `${key}:sign:${type}:write:${transport.uid}`); // action set to feecting parse 
    const feecting = await this.question(`${this.askChr}feecting parse:${transport.uid} ${text}`); // parse with feecting agent.
    
    this.state('return', `${key}:sign:${type}:return:${transport.uid}`); // set the state to return proxy
    return {
      text: feecting.a.text,
      html: feecting.a.html,
      data,
    }	  
    
  },
  
}
