export default {

  /**************
  method: security
  params: packet
  describe: The global security feature that installs with every agent
  ***************/
  security(packet) {
    const security = this.security();
    const data = {};
    return new Promise((resolve, reject) => {
      this.context('feature');
      this.question(`#docs raw feature/security`).then(doc => {
        data.doc = doc.a.data;
        const info = [
          `## Settings`,
          `::begin:security:${security.id}`,
          `client: ${security.client_name}`,
          `concerns: ${security.concerns.join(', ')}`,
          `::end:security:${this.hash(security)}`,
        ].join('\n');
        const text = doc.a.text.replace(/::info::/g, info)
        return this.question(`#feecting parse ${text}`)
      }).then(feecting => {
        return resolve({
          text: feecting.a.text,
          html: feecting.a.html,
          data: security
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
    this.feature('security');
    const id = this.uid();
    return Promise.resolve(id);
  },

  /**************
  method: md5 hash
  params: packet
  describe: Return system md5 hash for the based deva.
  ***************/
  hash(packet) {
    this.feature('security');
    const hash = this.hash(packet.q.text, 'md5');
    return Promise.resolve(hash);
  },

  /**************
  method: md5 cipher
  params: packet
  describe: Return system md5 hash for the based deva.
  ***************/
  cipher(packet) {
    this.feature('security');
    const data = this.cipher(packet.q.text);
    const cipher = `cipher: ${data.encrypted}`;
    return Promise.resolve(cipher);
  },
}
