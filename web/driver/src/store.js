// Where a driver keeps each swap: its record, the machine's state among
// it, saved after every step and before anything is sent or broadcast.

/** In IndexedDB, one record per swap id. Each save waits for a strict
 * commit, flushed to disk, before it resolves. */
export class IndexedDBStore {
  constructor(name = 'lattice-swap', indexedDB = globalThis.indexedDB) {
    this.database = new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore('swaps', { keyPath: 'swap_id' });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async #run(mode, act) {
    const database = await this.database;
    return new Promise((resolve, reject) => {
      const transaction = database.transaction('swaps', mode, { durability: 'strict' });
      const request = act(transaction.objectStore('swaps'));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  }

  load(swapId) {
    return this.#run('readonly', (swaps) => swaps.get(swapId)).then((record) => record ?? null);
  }

  save(record) {
    return this.#run('readwrite', (swaps) => swaps.put(structuredClone(record))).then(() => undefined);
  }

  list() {
    return this.#run('readonly', (swaps) => swaps.getAllKeys());
  }
}

/** In memory, for tests. */
export class MemoryStore {
  constructor() {
    this.records = new Map();
    this.saves = [];
  }

  async load(swapId) {
    const record = this.records.get(swapId);
    return record ? structuredClone(record) : null;
  }

  async save(record) {
    this.records.set(record.swap_id, structuredClone(record));
    this.saves.push(structuredClone(record));
  }

  async list() {
    return [...this.records.keys()];
  }
}
