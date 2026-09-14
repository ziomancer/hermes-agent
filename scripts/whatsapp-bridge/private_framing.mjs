// Strict private-channel JSON and bounded binary framing.
// HTTP authentication, continuing timers and producer ownership are caller gates.
import {createHash} from 'node:crypto';
function decimalForm(token){
  // Compare decimal values without constructing enormous powers. Ordinary
  // shortest round-trip decimals (including locations) remain representable;
  // a longer token silently rounded to another decimal value is rejected.
  const m=token.match(/^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/);
  let digits=(m[2]+(m[3]??'')).replace(/^0+/,'');
  if(!digits)return '0';
  const expText=m[4]??'0';if(expText.length>6)throw Error('number_precision');
  let exp=Number(expText)-(m[3]?.length??0);
  const tail=digits.match(/0+$/)?.[0].length??0;
  if(tail){digits=digits.slice(0,-tail);exp+=tail;}
  return m[1]+digits+'e'+exp;
}
export function strictJSON(bytes,maxBytes){
  if(bytes.length>maxBytes)throw Error('json_limit');
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  if(text.charCodeAt(0)===0xfeff)throw Error('bom');
  let i=0;
  const ws=()=>{while(/[\t\n\r ]/.test(text[i]??'x'))i++;};
  function string(){
    const start=i++;let escaped=false;
    for(;i<text.length;i++){
      const c=text[i];if(!escaped&&c==='"'){
        const value=JSON.parse(text.slice(start,++i));
        for(const cp of value){const n=cp.codePointAt(0);if(n>=0xd800&&n<=0xdfff)throw Error('surrogate');}
        return value;
      }
      if(!escaped&&c==='\\')escaped=true;else escaped=false;
    }
    throw Error('string');
  }
  function value(depth){
    if(depth>20)throw Error('depth');ws();const c=text[i];
    if(c==='"')return string();
    if(c==='['){i++;const out=[];ws();if(text[i]===']'){i++;return out;}
      for(;;){out.push(value(depth+1));ws();if(text[i]===']'){i++;return out;}if(text[i++]!==',')throw Error('array');}
    }
    if(c==='{'){i++;const out=Object.create(null),keys=new Set();ws();if(text[i]==='}'){i++;return out;}
      for(;;){ws();if(text[i]!=='"')throw Error('key');const key=string();if(keys.has(key))throw Error('duplicate_key');keys.add(key);ws();if(text[i++]!==':')throw Error('colon');out[key]=value(depth+1);ws();if(text[i]==='}'){i++;return out;}if(text[i++]!==',')throw Error('object');}
    }
    for(const [word,v] of [['null',null],['true',true],['false',false]])if(text.startsWith(word,i)){i+=word.length;return v;}
    const number=text.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if(!number)throw Error('value');i+=number[0].length;const n=Number(number[0]);if(!Number.isFinite(n))throw Error('nonfinite');
    if((Number.isInteger(n)&&!Number.isSafeInteger(n))||decimalForm(number[0])!==decimalForm(JSON.stringify(n)))throw Error('number_precision');
    return n;
  }
  const result=value(0);ws();if(i!==text.length)throw Error('trailing_json');return result;
}
export async function readFrame(source,{metadataLimit,payloadLimit,expectedBytes,expectedSHA,validateMetadata,consume}){
  // The owned HTTP caller retains one idle/total timer over prefix, metadata,
  // payload and sink operations. This parser never resets or replaces it.
  if(!Number.isSafeInteger(expectedBytes)||expectedBytes<0||expectedBytes>payloadLimit)throw Error('payload_limit');
  let prefix=Buffer.alloc(4),prefixUsed=0,metadata=null,metadataUsed=0,metaValue=null,count=0,maxPiece=0;
  const digest=createHash('sha256');
  for await(const incoming of source){
    // Node buffers may exceed a requested read size; operate on bounded views.
    for(let start=0;start<incoming.length;start+=65536){
      const piece=incoming.subarray(start,start+65536);maxPiece=Math.max(maxPiece,piece.length);let pos=0;
      if(prefixUsed<4){const n=Math.min(4-prefixUsed,piece.length);piece.copy(prefix,prefixUsed,0,n);prefixUsed+=n;pos+=n;
        if(prefixUsed===4){const length=prefix.readUInt32BE();if(length<1||length>metadataLimit)throw Error('metadata_limit');metadata=Buffer.alloc(length);}
      }
      if(prefixUsed<4)continue;
      if(metadataUsed<metadata.length){const n=Math.min(metadata.length-metadataUsed,piece.length-pos);piece.copy(metadata,metadataUsed,pos,pos+n);metadataUsed+=n;pos+=n;
        if(metadataUsed===metadata.length){metaValue=strictJSON(metadata,metadataLimit);validateMetadata(metaValue);}
      }
      if(metadataUsed<metadata.length)continue;
      const rest=piece.subarray(pos);if(count+rest.length>expectedBytes||count+rest.length>payloadLimit)throw Error('payload_excess');
      if(rest.length){digest.update(rest);count+=rest.length;await consume(rest);}
    }
  }
  if(prefixUsed!==4||metadataUsed!==metadata?.length)throw Error('frame_short');
  if(count!==expectedBytes)throw Error('payload_short');
  if(digest.digest('hex')!==expectedSHA)throw Error('payload_digest');
  return {metadata:metaValue,bytes:count,maxPiece};
}

// One retained request body. Only the controller constructs it from an
// authenticated HTTP stream; a delivery producer consumes it at most once.
export class PrivateUpload {
  #iterator;
  #pending = Buffer.alloc(0);
  #digest = createHash('sha256');
  #work = null;
  #cancelled = false;
  #complete = false;
  #abort;
  #onCancel = null;
  #metadata;
  #expected;
  #sha;
  #count = 0;
  #transportDigest = null;

  static async open(source, {metadataLimit, frameLimit, contentLength, validateMetadata, abort}) {
    const upload = new PrivateUpload();
    upload.#iterator = source[Symbol.asyncIterator]();
    upload.#abort = abort;
    try {
      const prefix = await upload.#exact(4);
      const length = prefix.readUInt32BE();
      if (length < 1 || length > metadataLimit) throw Error('metadata_limit');
      const raw = await upload.#exact(length);
      upload.#metadata = strictJSON(raw, metadataLimit);
      validateMetadata(upload.#metadata);
      upload.#expected = upload.#metadata.data.size;
      upload.#sha = upload.#metadata.data.sha256;
      if (!Number.isSafeInteger(contentLength) || contentLength > frameLimit ||
          contentLength !== 4 + length + upload.#expected) throw Error('payload_limit');
      return upload;
    } catch (error) {
      upload.cancel();
      await upload.join();
      throw error;
    }
  }

  get metadata() { return structuredClone(this.#metadata); }
  get complete() { return this.#complete; }
  get digest() { if (!this.#complete) throw Error('unknown'); return this.#transportDigest; }

  async #piece(limit = 65536) {
    if (this.#cancelled) throw Error('cancelled');
    if (!this.#pending.length) {
      const next = await this.#iterator.next();
      if (this.#cancelled) throw Error('cancelled');
      if (next.done) return null;
      if (!Buffer.isBuffer(next.value)) throw Error('invalid_schema');
      this.#pending = next.value;
    }
    const piece = this.#pending.subarray(0, Math.min(limit, 65536));
    this.#pending = this.#pending.subarray(piece.length);
    return piece;
  }

  async #exact(length) {
    const bytes = Buffer.alloc(length);
    let count = 0;
    while (count < length) {
      const piece = await this.#piece(length - count);
      if (piece === null) throw Error('frame_short');
      const used = Math.min(length - count, piece.length);
      piece.copy(bytes, count, 0, used);
      count += used;
    }
    this.#digest.update(bytes);
    return bytes;
  }

  consume(sink) {
    if (this.#work || this.#cancelled || typeof sink !== 'function') return Promise.reject(Error('conflict'));
    this.#work = (async () => {
      const hash = createHash('sha256');
      for (;;) {
        const piece = await this.#piece();
        if (piece === null) break;
        if (!piece.length) continue;
        this.#count += piece.length;
        if (this.#count > this.#expected) throw Error('payload_excess');
        hash.update(piece); this.#digest.update(piece);
        await sink(piece);
        if (this.#cancelled) throw Error('cancelled');
      }
      if (this.#count !== this.#expected) throw Error('payload_short');
      if (hash.digest('hex') !== this.#sha) throw Error('payload_digest');
      this.#transportDigest = this.#digest.digest('hex');
      this.#complete = true;
      return true;
    })();
    // Retain the original promise; a rejection is observed even if a producer
    // throws after beginning the sink. join never substitutes a timeout for it.
    this.#work.catch(() => {});
    return this.#work;
  }

  onCancel(callback) {
    if (this.#onCancel || typeof callback !== 'function') throw Error('conflict');
    this.#onCancel = callback;
    if (this.#cancelled) callback();
  }
  cancel() {
    if (this.#cancelled) return;
    this.#cancelled = true;
    this.#abort();
    this.#onCancel?.();
  }
  async join() {
    try { await this.#work; } catch { /* failed transfer still must join */ }
    if (!this.#complete && !this.#cancelled) return false;
    try { await this.#iterator.return?.(); } catch { return false; }
    this.#pending = Buffer.alloc(0);
    return true;
  }
}
