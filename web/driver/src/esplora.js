// Bitcoin through an Esplora API, as mempool.space and blockstream.info
// serve one: the reads a buyer's view needs, and broadcasts.

/** One Esplora API at `url`, e.g. `https://mempool.space/api`. */
export class Esplora {
  constructor(url, fetchImpl = globalThis.fetch) {
    this.url = url.replace(/\/+$/, '');
    this.fetch = fetchImpl;
  }

  /** The answer's text; null on 404 if `missing` is allowed. */
  async #get(path, missing = false) {
    const response = await this.fetch(`${this.url}${path}`, { cache: 'no-store' });
    if (missing && response.status === 404) return null;
    if (!response.ok) throw new Error(`${this.url}${path}: ${response.status} ${await response.text()}`);
    return response.text();
  }

  /** The tip as `swap::view::Tip`: Esplora shows its blocks, not a header
   * chain ahead of them, so `headers` is the tip's own height. */
  async tip() {
    const hash = (await this.#get('/blocks/tip/hash')).trim();
    const block = JSON.parse(await this.#get(`/block/${hash}`));
    return { height: block.height, headers: block.height, time: block.timestamp, hash };
  }

  /** A transaction, if Esplora holds it: `{hex, height}`, `height` null in
   * the mempool. `/tx/{txid}` answers 404 for one it never saw; its
   * `/status` would answer unconfirmed. */
  async transaction(txid) {
    const tx = await this.#get(`/tx/${txid}`, true);
    if (tx === null) return null;
    const { status } = JSON.parse(tx);
    const hex = await this.#get(`/tx/${txid}/hex`, true);
    if (hex === null) return null;
    return { hex: hex.trim(), height: status.confirmed ? status.block_height : null };
  }

  /** The txid that spends `txid:vout`, in the mempool or a block, if any. */
  async spender(txid, vout) {
    const spend = JSON.parse(await this.#get(`/tx/${txid}/outspend/${vout}`));
    return spend.spent ? spend.txid : null;
  }

  /** What pays `address`: `[{txid, vout, value, height}]`, `height` null
   * in the mempool. */
  async utxos(address) {
    const utxos = JSON.parse(await this.#get(`/address/${address}/utxo`));
    return utxos.map(({ txid, vout, value, status }) => ({
      txid,
      vout,
      value,
      height: status.confirmed ? status.block_height : null,
    }));
  }

  /** The fee rate, in sat/vB, to confirm within `blocks`, or null. */
  async feeRate(blocks) {
    const estimates = JSON.parse(await this.#get('/fee-estimates'));
    const rate = estimates[String(blocks)];
    return typeof rate === 'number' ? rate : null;
  }

  /** Broadcasts `hex`; throws with Esplora's reason if it refuses it. */
  async broadcast(hex) {
    const response = await this.fetch(`${this.url}/tx`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: hex,
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`${this.url}: ${response.status} ${text}`);
    return text.trim();
  }
}
