module.exports = {
  /**************
  method: security
  params: packet
  describe: The global security feature that installs with every agent
  ***************/
  security(packet) {
    this.context('feature');
    const security = this.security();
    const data = {};
    return new Promise((resolve, reject) => {
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
    this.context('uid');
    this.feature('security');
    return Promise.resolve(this.uid());
  },
}
