// Where the page keeps its wallet key and each swap's record. A record is
// saved before anything it asks for is sent or broadcast, as the native
// driver saves its swap file.

/** In IndexedDB, one value per key. Each write waits for a strict commit,
 * flushed to disk, before it resolves. */
export class IndexedDBStore {
  constructor(name = 'lattice-swap', indexedDB = globalThis.indexedDB) {
    this.database = new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore('records');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async #run(mode, act) {
    const database = await this.database;
    return new Promise((resolve, reject) => {
      const transaction = database.transaction('records', mode, { durability: 'strict' });
      const request = act(transaction.objectStore('records'));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  }

  async get(key) {
    return (await this.#run('readonly', (records) => records.get(key))) ?? null;
  }

  async put(key, value) {
    await this.#run('readwrite', (records) => records.put(structuredClone(value), key));
  }

  /** Writes `value` at `key` only if nothing is there: IndexedDB's `add`,
   * which refuses to overwrite. */
  async add(key, value) {
    await this.#run('readwrite', (records) => {
      const request = records.add(structuredClone(value), key);
      // A key already there is no failure: the transaction commits.
      request.onerror = (event) => {
        if (request.error.name !== 'ConstraintError') return;
        event.preventDefault();
        event.stopPropagation();
      };
      return request;
    });
  }

  async delete(key) {
    await this.#run('readwrite', (records) => records.delete(key));
  }

  keys() {
    return this.#run('readonly', (records) => records.getAllKeys());
  }
}

/** In memory, for tests: `puts` logs every write. */
export class MemoryStore {
  constructor() {
    this.values = new Map();
    this.puts = [];
  }

  async get(key) {
    return this.values.has(key) ? structuredClone(this.values.get(key)) : null;
  }

  async put(key, value) {
    this.values.set(key, structuredClone(value));
    this.puts.push([key, structuredClone(value)]);
  }

  async add(key, value) {
    if (!this.values.has(key)) await this.put(key, value);
  }

  async delete(key) {
    this.values.delete(key);
  }

  async keys() {
    return [...this.values.keys()];
  }
}
