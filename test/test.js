import { promises as fs } from 'fs';
import test from 'tape';
import buffer from 'buffer';
import { sparkey_openHash, 
         sparkey_logiter_create,
         sparkey_logiter_next,
         sparkey_returncode,
         sparkey_iterator_state,
         sparkey_logiter_keychunk,
         sparkey_logiter_valuechunk,
         sparkey_get,
         sparkey_logiter_close,
         sparkey_closeHash
        } from '../lib/index.js';

test('find keys', async function (t) {
  const sparkeyPath = './test/';
  const sparkeyTable = 'sparkey1million';

  const sampleIndexFile = sparkeyPath + sparkeyTable + '.spi';
  const sampleLogFile = sparkeyPath + sparkeyTable + '.spl';
  const keysFile = sparkeyPath + sparkeyTable + '.csv';

  const keyFileContents = await fs.readFile(keysFile, 'utf-8');
  const lookupKeys = keyFileContents.split('\n').filter(k => k.length > 0).map(k => Buffer.from(k));

  t.equal(lookupKeys.length, 100000);

  let hashReader = await sparkey_openHash(sampleIndexFile, sampleLogFile);
  let logIterator = sparkey_logiter_create(hashReader.log);

  var iterate_example = true;
  var get_example = true;

  if(iterate_example) {
    let count = 0;
    let stride = 1;
    while(count < 10) {// eslint-disable-line no-constant-condition
      let rc = sparkey_logiter_next(logIterator, hashReader.log);
      if(rc !== sparkey_returncode.SPARKEY_SUCCESS || logIterator.state != sparkey_iterator_state.SPARKEY_ITER_ACTIVE) {
        break;
      }
      count ++;
      let bo = logIterator.block_offset;

      let key_result = sparkey_logiter_keychunk(logIterator, hashReader.log, hashReader.log.header.max_key_len); 
      let k = key_result.buffer.slice(0,Number(key_result.chunk_length)).toString();

      let value_result = sparkey_logiter_valuechunk(logIterator, hashReader.log, hashReader.log.header.max_value_len);
      console.log(`value result ${value_result.chunk_length}`);
      let v = value_result.buffer.slice(0,Number(value_result.chunk_length)).toString();

      if(count % stride == 0) {
        console.log(`Key: "${k}" Value: "${v}"`);
      }
      
      logIterator.block_offset = bo;
    }
  }
  
  if(get_example) {
    // Create buffer for retrieved values
    let valueBuffer = Buffer.alloc(Number(hashReader.log.header.max_value_len));

    let found = 0;
    let not_found = 0;

    console.log(`Performing lookup on ${lookupKeys.length} keys.`);
    console.time('lookups');

    // max buffer should be the size of the hash file or the max buffer allowed
    let max_buffer = BigInt(buffer.constants.MAX_LENGTH);
    if(max_buffer > hashReader.data_len) {
      max_buffer = hashReader.data_len;
    }
    // TODO add some helpers to manage this
    hashReader.max_buffer = max_buffer;
    hashReader.buffer_start = 0n;
    hashReader.buffer_length = max_buffer;
    hashReader.buffer = hashReader.mmapping.getBuffer(hashReader.buffer_start + BigInt(hashReader.header.header_size), hashReader.buffer_length);

    lookupKeys.forEach(lookupKeyBuf => {
      console.log(`lookup ${lookupKeyBuf.toString()}`);
      let result = sparkey_get(hashReader, logIterator, lookupKeyBuf, valueBuffer);
      if(result.found) {
        found += 1;
        // verify the data has the format {value: true or false, keyrev: key matches record key}
        let value = valueBuffer.slice(0, result.length).toString();
        let parsed = JSON.parse(value);
        t.equal(typeof parsed.value, 'boolean');
        t.equal(parsed.keyrev, lookupKeyBuf.toString());
      } else {
        not_found += 1;
      }
    });

    console.timeEnd('lookups');
    console.log(`found count ${found}, not found count ${not_found}`);
    t.equal(found, 99995);
    t.equal(not_found, 5);
    t.equal(100000, found + not_found);
  }

  sparkey_logiter_close(logIterator);
  await sparkey_closeHash(hashReader);

  t.end();
});
