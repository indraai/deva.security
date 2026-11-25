# Security Deva

Security Deva is the security agent for Indra.ai and Deva.world. Its agent key is `security`. It keeps a chain-of-custody log of `devacore:finish` and `devacore:complete` packets in a MongoDB log database, and it ships the security feature methods that the feature loader binds at runtime: `security`, `uid`, `sign`, `hash`, `encrypt`, `decrypt`, `date`, and `time`. Commands talk to it directly with `/uid` or, from another Deva, with `#security uid`.

## Requirements

- Node.js with npm. Security Deva's `package.json` sets no `engines`. Deva Core 1.67.26 declares `"node": ">=22"` and `"npm": ">=9.5.1"` in its own `package.json`.
- A project with `"type": "module"` in its `package.json`. Security Deva is an ES module.
- `@indra.ai/deva` `^1.67.26` (Deva Core) and `mongodb` `^7.9.1`. Both install with Security Deva.
- A MongoDB server if you want the chain-of-custody logs saved. A local `mongod` at `mongodb://127.0.0.1:27017` is enough.

## Install

```bash
npm install @indra.ai/deva.security --save
```

```js
import SecurityDeva from '@indra.ai/deva.security';
```

## Two licenses

A running Deva carries two separate licenses, and each is checked on its own.

- **The core license** comes through the client data as `client.VLA`. Deva Core checks it against the core package's VLA at the start of `init`.
- **The agent license** comes through the license feature data as `features.license.devas.security`. Deva Core 1.67.26 checks it against the VLA in Security Deva's own `package.json` right after the features load and before `onInit`. Security Deva has no `onInit` of its own, so it has no license check of its own to change or remove.

The agent check compares the sha256 of the whole VLA object, so every field has to match exactly.

## Configuration

Security Deva reads two features from the client you pass to `init()`. The feature data loader puts them in the client, and Deva Core loads them into the Deva at startup, so both must be there before `init()` runs.

```json
"features": {
	"license": {
		"concerns": [],
		"global": [],
		"devas": {
			"security": {"uid": "15266350905933520771"}
		}
	},
	"security": {
		"concerns": [],
		"global": {
			"mongo": {
				"uri": "mongodb://127.0.0.1:27017",
				"database": "SecurityDeva",
				"log": "SecurityDevaLog"
			}
		},
		"devas": {
			"security": {
				"mongo": {
					"uri": "mongodb://127.0.0.1:27017",
					"database": "SecurityDeva",
					"log": "SecurityDevaLog"
				}
			}
		}
	}
}
```

- `license.devas.security` is the agent VLA. The short form above only shows where it goes. It must be the full `VLA` object from this package's `package.json`, for example:

```js
import pkg from '@indra.ai/deva.security/package.json' with {type:'json'};

const devas = {security: pkg.VLA}; // goes in features.license.devas
```

- `security.global.mongo.uri` is the MongoDB connection string. If it is not set, Security Deva still comes online but builds no MongoDB client.
- `security.global.mongo.database` is the main database name. `onReady` stores it in `this.vars.database`.
- `security.global.mongo.log` is the log database name. `onReady` stores it in `this.vars.log`. `func.write_log` inserts into a named collection in that database.
- The tests also set `security.devas.security` with the same `{uri, database, log}` shape. That is the personal record for this agent (`agent.key` is `security`). Deva Core exposes it as `this.security().personal`. `onReady` and `write_log` read only `this.security().global?.mongo`. They do not use the personal record. The feature methods `hash`, `encrypt`, and `decrypt` also call `this.security()` for `global` and `personal` values such as the hash algorithm and encrypt options.

## Load it

```js
import SecurityDeva from '@indra.ai/deva.security';

const security = await SecurityDeva.init(client); // client data provided by your loader
console.log(security.id.uid);
```

When the license checks pass, Security Deva walks start, enter, done and ready. In `onReady` it reads `this.security().global?.mongo`, builds a `MongoClient` in `this.modules.client` when `uri` is set, keeps `database` in `this.vars.database` and `log` in `this.vars.log`, and prompts `🚨 Security Deva Ready > VLA:15266350905933520771`.

To shut it down:

```js
await SecurityDeva.stop();
```

`onStop` closes the MongoDB client, if there is one, then calls `this.close(data, resolve)`. If there is no client, it calls `this.close(data, resolve)` directly. A stopped Deva can start again. Call `init()` again with a client that passes the license check. Security Deva builds a new MongoDB client in `onReady`.

## When Security Deva refuses to start

If the agent license check fails, Deva Core prompts the message, stops the Deva, and `init()` resolves with that message.

| You see | Why |
| --- | --- |
| `❌ Bad Personal VLA` | `features.license.devas` is there but has no `security` entry. |
| `❌ Invalid VLA Check` | The `security` entry doesn't match this package's VLA, or the license feature has no `devas`. |

## Commands

Talk to Security Deva with `/uid` when it is the current agent, or with `#security uid` from another Deva, after the feature loader has bound `feature/methods.js`. The same pattern applies to the other feature methods.

| Command | What it does |
| --- | --- |
| `/security` | Calls `this.methods.sign('security', 'default', packet)` and returns that result. |
| `/uid` | Builds a system uid with `this.uid()`, formats it as a Feecting license block, and asks Feecting to parse it. It returns `{text, html, data}`, where `data` is the uid object. A first parameter of a truthy value, from `packet.q.meta.params[1]`, also appends the uid as JSON. |
| `/sign` | Calls `this.sign(packet)`, formats the signature as a Feecting block, and asks Feecting to parse it. It returns `{text, html, data}`. |
| `/hash` | Hashes `packet.q.text` with `this.hash`. The algorithm is `packet.q.meta.params[1]`, or `personal.hash`, or `global.hash` from `this.security()`. It asks Feecting to parse the result and returns `{text, html, data}`. |
| `/encrypt` | Encrypts `packet.q.text` with `this.lib.encrypt` using `global.encrypt` from `this.security()`. It adds md5, sha256, and sha512 hashes of the ciphertext and returns `{text, html: false, data}`. |
| `/decrypt` | Decrypts `packet.q.text` with `this.lib.decrypt`. The iv is `packet.q.meta.params[1]`, the key is `params[2]`, and the algorithm is `global.encrypt.algorithm` from `this.security()`. It adds the same three hash tiers of the plaintext and returns `{text, html: false, data}`. |
| `/date` | Formats the current time with `this.lib.formatDate`. The format is `params[1]` or `long`, and `params[2]` controls whether the time is included. It asks Feecting to parse the result and returns `{text, html, data}`. |
| `/time` | Returns `Date.now()` as a resolved Promise. The resolved value is the timestamp number, not a `{text, html, data}` object. |

## Functions

| Func | What it does |
| --- | --- |
| `write_log` | Inserts `packet` into collection `type` in `this.vars.log`, using the one `MongoClient` in `this.modules.client`. It returns the `insertOne` result. The `devacore:finish` and `devacore:complete` listeners call it with `'finish'` and `'complete'` when the Deva is active. There is no try/catch in `func.write_log`; a missing client or a failed insert throws. |

## Feature methods

`feature/methods.js` exports `security`, `uid`, `sign`, `hash`, `encrypt`, `decrypt`, `date`, and `time`. The feature loader binds them at runtime from `client.features.security.methods` onto the Deva's `methods`. `index.js` itself ships `methods: {}`. The `security(packet)` method is the global security feature that installs with every agent.

## Help

Help lives in Feecting files. `help/main.feecting` is the main help page, with the heading `{{profile.name}}`, the security protocols block, and the license block. `help/corpus.feecting` is the help corpus. `help/frameworks/HigherVGW.feecting` is the Higher Vector Guard Wall writeup. `help/programs/KingdomSecureProtectionArm.feecting` is the Kingdom Secure Protection Arm program. The tests check that the main heading is there and that the license page carries this package's VLA uid and hash tiers.

## Inside Security Deva

| Name | Kind | What it does |
| --- | --- | --- |
| `write_log` | func | Inserts a packet into a named collection in the log database, as described above. It lives in `index.js`. |
| `security`, `uid`, `sign`, `hash`, `encrypt`, `decrypt`, `date`, `time` | feature methods | The commands in `feature/methods.js`, bound at runtime. |
| `translate`, `parse`, `process` | utils | Each returns its input trimmed. |
| `onReady` | lifecycle | Builds the MongoDB client from the security feature's `global.mongo` and prompts the ready message. |
| `onStop` | lifecycle | Closes the MongoDB client, if there is one, then calls `this.close(data, resolve)`. |
| `onError` | lifecycle | Prompts `💣 ERROR!`, logs the error with `console.error`, and returns `reject(err)` or `Promise.reject(err)`. |
| `modules.client` | module | The `MongoClient`, set in `onReady` when a `uri` is given. |

The `vars` in `package.json` hold the prompt `messages`, the `@SECURITY` trigger, and context labels. `this.vars.database` and `this.vars.log` are set in `onReady` from `global.mongo.database` and `global.mongo.log`. The `devacore:finish` and `devacore:complete` listeners copy the packet and pass it to `write_log` when `this._active` is true.

## Testing

Start a local MongoDB, then run:

```bash
node --test
```

The draft `index.test.js` is written for `node --test`. Once the package.json `test` script is set to `node --test`, `npm test` runs the same file. The tests use `mongodb://127.0.0.1:27017` by default. To use another server, set `MONGO_URI`:

```bash
MONGO_URI="mongodb://127.0.0.1:27018" node --test
```

The tests always write to their own databases, `deva_security_test` and `deva_security_log_test`, and drop them when they finish. Only the server can change, so the cleanup never touches another database. If MongoDB can't be reached, the MongoDB insert tests are skipped with a message and the rest still run, including the check that `write_log` rejects when no MongoDB client is built, and the check that `init` with `MONGO_URI=mongodb://127.0.0.1:1` still reaches ready.

The tests build a stub client in code from the core VLA in `@indra.ai/deva/package.json` and the VLA in this package's `package.json`, so no client file is needed. They cover:

- security builds as a Deva and waits offline before init
- security data has no placeholders left
- `func.write_log`, `onReady`, `onStop`, and `onError` exist
- security comes online and walks to ready
- security agent matches the package
- security utils answer with trimmed text
- security help pages name the Deva and carry the package license
- feature methods from `feature/methods.js` load at runtime
- `onReady` reads mongo from `this.security()`, not from another Deva
- `init` with an unreachable MongoDB uri still reaches ready
- `write_log` inserts a document into the `finish` collection (MongoDB)
- `write_log` rejects when no MongoDB client is built
- a stop and `init` restart builds a new MongoClient and can write_log again (MongoDB)
- security stops through the full chain
- security refuses to start with a bad agent VLA

## Files

| File | What it holds |
| --- | --- |
| `index.js` | The Security Deva: utils, `func.write_log`, the finish and complete listeners, and the lifecycle hooks. |
| `package.json` | Package info, the package VLA, and the agent, vars, zones, actions, and states data under `data`. |
| `feature/methods.js` | The security feature methods that the feature loader binds at runtime. |
| `help/main.feecting` | The main help page and the license block. |
| `help/corpus.feecting` | The help corpus. |
| `help/frameworks/HigherVGW.feecting` | The Higher Vector Guard Wall writeup. |
| `help/programs/KingdomSecureProtectionArm.feecting` | The Kingdom Secure Protection Arm program. |
| `index.test.js` | The tests. |
| `assets/` | The emoji, avatar, background and image files. |
| `LICENSE.md` | The license. |

Copyright ©2000-2026 Quinn Michaels; All rights reserved.  
Owner Signature Required For Lawful Use.  
Distributed under VLA:15266350905933520771 LICENSE.md  
Wednesday, November 25, 2026 - 9:44:25 AM PST
