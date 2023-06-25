const fs = require('fs').promises;
const mhn = require('murmurhash-native');
const mmap = require('mmap-utils');

const HASH_MAGIC_NUMBER = 0x9a11318f;
const HASH_MAJOR_VERSION = 1;
const HASH_MINOR_VERSION = 1;
const HASH_HEADER_SIZE= 112;

const MAGIC_VALUE_LOGITER = 0xd765c8cc;
const MAGIC_VALUE_HASHREADER = 0x75103df9;

const LOG_MAGIC_NUMBER = 0x49b39c95;
const LOG_MAJOR_VERSION = 1;
const LOG_MINOR_VERSION = 0;
const LOG_HEADER_SIZE = 84;

const sparkey_returncode = {
  SPARKEY_SUCCESS: 0,
  SPARKEY_INTERNAL_ERROR: -1,

  SPARKEY_FILE_NOT_FOUND: -100,
  SPARKEY_PERMISSION_DENIED: -101,
  SPARKEY_TOO_MANY_OPEN_FILES: -102,
  SPARKEY_FILE_TOO_LARGE: -103,
  SPARKEY_FILE_ALREADY_EXISTS: -104,
  SPARKEY_FILE_BUSY: -105,
  SPARKEY_FILE_IS_DIRECTORY: -106,
  SPARKEY_FILE_SIZE_EXCEEDED: -107,
  SPARKEY_FILE_CLOSED: -108,
  SPARKEY_OUT_OF_DISK: -109,
  SPARKEY_UNEXPECTED_EOF: -110,
  SPARKEY_MMAP_FAILED: -111,

  SPARKEY_WRONG_LOG_MAGIC_NUMBER: -200,
  SPARKEY_WRONG_LOG_MAJOR_VERSION: -201,
  SPARKEY_UNSUPPORTED_LOG_MINOR_VERSION: -202,
  SPARKEY_LOG_TOO_SMALL: -203,
  SPARKEY_LOG_CLOSED: -204,
  SPARKEY_LOG_ITERATOR_INACTIVE: -205,
  SPARKEY_LOG_ITERATOR_MISMATCH: -206,
  SPARKEY_LOG_ITERATOR_CLOSED: -207,
  SPARKEY_LOG_HEADER_CORRUPT: -208,
  SPARKEY_INVALID_COMPRESSION_BLOCK_SIZE: -209,
  SPARKEY_INVALID_COMPRESSION_TYPE: -210,

  SPARKEY_WRONG_HASH_MAGIC_NUMBER: -300,
  SPARKEY_WRONG_HASH_MAJOR_VERSION: -301,
  SPARKEY_UNSUPPORTED_HASH_MINOR_VERSION: -302,
  SPARKEY_HASH_TOO_SMALL: -303,
  SPARKEY_HASH_CLOSED: -304,
  SPARKEY_FILE_IDENTIFIER_MISMATCH: -305,
  SPARKEY_HASH_HEADER_CORRUPT: -306,
  SPARKEY_HASH_SIZE_INVALID: -307,
};

// const MAGIC_VALUE_LOGITER = 0xd765c8cc;
const MAGIC_VALUE_LOGREADER = 0xe93356c4;

const sparkey_iterator_state = {
  SPARKEY_ITER_NEW: 0,
  SPARKEY_ITER_ACTIVE: 1,
  SPARKEY_ITER_CLOSED: 2,
  SPARKEY_ITER_INVALID: 3
};

const sparkey_compression_type = {
  SPARKEY_COMPRESSION_NONE: 0,
  SPARKEY_COMPRESSION_SNAPPY: 1,
  SPARKEY_COMPRESSION_ZSTD: 2
};

const sparkey_entry_type = {
  SPARKEY_ENTRY_PUT: 0,
  SPARKEY_ENTRY_DELETE: 1
};

// Allow string conversion of BigInt
BigInt.prototype.toJSON = function() { return this.toString() }

function bigIntToNumberDivision(dividend, divisor) {
  return Number(dividend*1000n/divisor)/1000.0;
}

// Helper to read 4 byte integers to Number
async function readUint32(fp, buf) {
  await fp.read(buf, 0, 4);
  return buf.readUint32LE(0);
}

// Helper to read 8 byte integers to BigInt so precision is not lost
async function readUint64(fp, buf) {
  await fp.read(buf, 0, 8);
  return buf.readBigUint64LE(0);
}

// Some of Sparkey code base uses 64 bit numbers
// This asserts it is safe to do so and throws if not
function assert_safe_int(num) {
  let converted = Number(num);
  if(!Number.isSafeInteger(converted)) {
    throw new Error(`${num} to large to be used as an integer`)
  }
}

// Debug info about the hash header, not needed for production
function hashHeaderToString(header) {

  let average_displacement = bigIntToNumberDivision(header.total_displacement, header.num_entries);

  return `Hash file version ${header.major_version}.${header.minor_version}
Identifier: ${header.file_identifier.toString(16)}
Max key size: ${header.max_key_len}, Max value size: ${header.max_value_len}
Hash size: ${8*header.hash_size} bit Murmurhash3
Num entries: ${header.num_entries}, Capacity: ${header.hash_capacity}
Num collisions: ${header.hash_collisions}, Max displacement: ${header.max_displacement}, Average displacement: ${average_displacement}
Data size: ${header.data_end}, Garbage size: ${header.garbage_size}`
}

// Read the hash file and parse the header into an Object
async function loadHashHeader(index_file_path) {
  const fileHandle = await fs.open(index_file_path, 'r');
  const readBuffer = Buffer.alloc(8);
  await fileHandle.read(readBuffer, 0, 4);

  const magicNumber = readBuffer.readUInt32LE(0);
  if(magicNumber !== HASH_MAGIC_NUMBER) {
    throw new Error('Invalid magic number for index');
  }
  let h = {};
  await fileHandle.read(readBuffer, 0, 8);
  let majorVersion = readBuffer.readUint32LE(0);
  let minorVersion = readBuffer.readUint32LE(4);

  if(majorVersion != HASH_MAJOR_VERSION || minorVersion > HASH_MINOR_VERSION) {
    throw new Error(`Hash file version mismatch. File version ${majorVersion}.${minorVersion} does not match ${HASH_MAJOR_VERSION}.${HASH_MINOR_VERSION}`);
  }

  h.major_version = majorVersion;
  h.minor_version = minorVersion;

  h.file_identifier = await readUint32(fileHandle, readBuffer);
  h.hash_seed = await readUint32(fileHandle, readBuffer);
  h.data_end = await readUint64(fileHandle, readBuffer);
  h.max_key_len = await readUint64(fileHandle, readBuffer);
  h.max_value_len = await readUint64(fileHandle, readBuffer);
  h.num_puts = await readUint64(fileHandle, readBuffer);
  h.garbage_size = await readUint64(fileHandle, readBuffer);
  h.num_entries = await readUint64(fileHandle, readBuffer);

  h.address_size = await readUint32(fileHandle, readBuffer);
  h.hash_size = await readUint32(fileHandle, readBuffer);
  h.hash_capacity = await readUint64(fileHandle, readBuffer);
  h.max_displacement = await readUint64(fileHandle, readBuffer);
  h.entry_block_bits = await readUint32(fileHandle, readBuffer);
  h.entry_block_bitmask = (1 << h.entry_block_bits) -1;
  h.hash_collisions = await readUint64(fileHandle, readBuffer);
  h.total_displacement = await readUint64(fileHandle, readBuffer);
  h.header_size = HASH_HEADER_SIZE;

  if(h.hash_size === 4) {
    h.hash_algorithm = mhn.murmurHash32;
  } else if(h.hash_size === 8) {
    h.hash_algorithm = mhn.murmurHash64;
  } else {
    throw new Error(`No hash algorithm for hash size ${h.hash_size}`);
  }

  // Some basic consistency checks
  if(h.num_entries > h.num_puts) {
    throw new Error("SPARKEY_HASH_HEADER_CORRUPT");
  }
  if(h.max_displacement > h.num_entries) {
    throw new Error("SPARKEY_HASH_HEADER_CORRUPT");
  }
  if(h.hash_collisions > h.num_entries) {
    throw new Error("SPARKEY_HASH_HEADER_CORRUPT");
  }

  await fileHandle.close();
  return h;
}

// Read the log header and parse into an Object
async function loadLogHeader(log_file_path) {
  const fileHandle = await fs.open(log_file_path, 'r');
  const readBuffer = Buffer.alloc(8);
  await fileHandle.read(readBuffer, 0, 4);

  const magicNumber = readBuffer.readUInt32LE(0);
  if(magicNumber !== LOG_MAGIC_NUMBER) {
    throw new Error('Invalid magic number for log');
  }
  let h = {};
  await fileHandle.read(readBuffer, 0, 8);
  let majorVersion = readBuffer.readUint32LE(0);
  let minorVersion = readBuffer.readUint32LE(4);

  if(majorVersion != LOG_MAJOR_VERSION || minorVersion > LOG_MINOR_VERSION) {
    throw new Error(`Log file version mismatch. File version ${majorVersion}.${minorVersion} does not match ${LOG_MAJOR_VERSION}.${LOG_MAJOR_VERSION}`);
  }

  h.major_version = majorVersion;
  h.minor_version = minorVersion;

  h.file_identifier = await readUint32(fileHandle, readBuffer);
  h.num_puts = await readUint64(fileHandle, readBuffer);
  h.num_deletes = await readUint64(fileHandle, readBuffer);
  h.data_end = await readUint64(fileHandle, readBuffer);
  h.max_key_len = await readUint64(fileHandle, readBuffer);
  h.max_value_len = await readUint64(fileHandle, readBuffer);
  h.delete_size = await readUint64(fileHandle, readBuffer);
  h.compression_type = await readUint32(fileHandle, readBuffer);
  h.compression_block_size = await readUint32(fileHandle, readBuffer);
  h.put_size = await readUint64(fileHandle, readBuffer);
  h.max_entries_per_block = await readUint32(fileHandle, readBuffer);
  h.header_size = LOG_HEADER_SIZE;

  // Some basic consistency checks
  if(h.data_end < h.header_size) {
    throw new Error("SPARKEY_LOG_HEADER_CORRUPT");
  }
  if(h.num_puts > h.data_end) {
    throw new Error("SPARKEY_LOG_HEADER_CORRUPT");
  }
  if(h.num_deletes > h.data_end) {
    throw new Error("SPARKEY_LOG_HEADER_CORRUPT");
  }
  if(h.compression_type > sparkey_compression_type.SPARKEY_COMPRESSION_ZSTD) {
    throw new Error("SPARKEY_LOG_HEADER_CORRUPT");
  }

  // console.log(JSON.stringify(h));
  return h;
}

async function openLog(log_file_path) {
  let log = {};
  log.header = await loadLogHeader(log_file_path);

  log.data_len = log.header.data_end;

  let fd = await fs.open(log_file_path, 'r');
  let stats = await fd.stat();

  let error = null;

  if(log.data_len > stats.size) {
    error = "SPARKEY_LOG_TOO_SMALL";
  } 

  if(!error) {
    log.fd = fd;
    log.data = mmap.map(Number(log.data_len), mmap.PROT_READ, mmap.MAP_SHARED, log.fd.fd);
    log.open_status = MAGIC_VALUE_LOGREADER;
  }

  if(error) {
    console.log("ERROR");
    await fd.close();
    throw new Error(error);
  }

  return log;
}

// Closes the log file
async function closeLog(log) {
  await log.fd.close();
  log.fd = null;
}

// Open a hash file, map its contents to memory
async function openHash(index_file_path, log_file_path) {
  let reader = {};
  reader.header = await loadHashHeader(index_file_path); 
  // console.log(hashHeaderToString(reader.header));
  reader.log = await openLog(log_file_path); 

  let error = null;

  if(reader.header.file_identifier != reader.log.header.file_identifier) {
    error = "SPARKEY_FILE_IDENTIFIER_MISMATCH";
  }
  else if(reader.header.data_end > reader.log.header.data_end) {
    error = "SPARKEY_HASH_HEADER_CORRUPT";
  }
  else if(reader.header.max_key_len > reader.log.header.max_key_len) {
    error = "SPARKEY_HASH_HEADER_CORRUPT";
  }
  else if(reader.header.max_value_len > reader.log.header.max_value_len) {
    error = "SPARKEY_HASH_HEADER_CORRUPT";
  }

  reader.fd = await fs.open(index_file_path, 'r');
  let stats = await reader.fd.stat();

  reader.data_len = BigInt(reader.header.header_size) + reader.header.hash_capacity * 
                    (BigInt(reader.header.hash_size) + BigInt(reader.header.address_size));

  if(reader.data_len > stats.size) {
    error = "SPARKEY_LOG_TOO_SMALL";
  } 

  reader.data = mmap.map(Number(reader.data_len), mmap.PROT_READ, mmap.MAP_SHARED, reader.fd.fd);
  reader.open_status = MAGIC_VALUE_HASHREADER;

  return reader;
}

function read_addr(hashtable, pos, address_size) {
  let offset = Number(pos);
  assert_safe_int(pos);
  switch (address_size) {
    case 4: return BigInt(hashtable.readUint32LE(offset));
    case 8: return hashtable.readBigUint64LE(offset);
  }
  return -1n;
}

function read_hash(hashtable, pos, hash_size) {
  let offset = Number(pos);
  if(!Number.isSafeInteger(offset)) {
    throw new Error(`Offset too large for Buffer methods (${pos})`)
  }

  switch (hash_size) {
    case 4: return BigInt(hashtable.readUint32LE(offset));
    case 8: return hashtable.readBigUint64LE(offset);
  }
  throw new Error(`Unsupported hash type ${hash_size}`)
}

function assert_log_open(log) {
  if(log.open_status !== MAGIC_VALUE_LOGREADER) {
    throw new Error('SPARKEY_LOG_CLOSED');
  }
}

function assert_iter_open(iter, log) {
  assert_log_open(log);
  if(iter.open_status !== MAGIC_VALUE_LOGITER) {
    throw new Error('SPARKEY_LOG_ITERATOR_CLOSED');
  }
  if(iter.file_identifier !== log.header.file_identifier) {
    throw new Error('SPARKEY_LOG_ITERATOR_MISMATCH');
  }
  return sparkey_returncode.SPARKEY_SUCCESS;
}

function seekblock(iter, log, position) {
  iter.block_offset = 0n;
  if(iter.block_position === position) {
    return sparkey_returncode.SPARKEY_SUCCESS;
  }
  if(log.header.compression_type !== sparkey_compression_type.SPARKEY_COMPRESSION_NONE) {
    throw new Error('compression not implemented');
    // uint64_t pos = position;
    // // TODO: assert that we're not reading > uint32_t
    // uint32_t compressed_size = read_vlq(log.data, &pos);
    // uint64_t next_pos = pos + compressed_size;
    // uint32_t uncompressed_size = log.header.compression_block_size;

    // sparkey_returncode ret = sparkey_compressors[log.header.compression_type].decompress(
    //   &log.data[pos], compressed_size, iter.compression_buf, &uncompressed_size);
    // if (ret !== sparkey_returncode.SPARKEY_SUCCESS) {
    //   return ret;
    // }

    // iter.block_position = position;
    // iter.next_block_position = next_pos;
    // iter.block_len = uncompressed_size;
  } else {
    // iter.compression_buf = &log.data[position];
    assert_safe_int(position); // TODO this could return Number
    iter.compression_buf = log.data.slice(Number(position));
    iter.block_position = position;
    iter.next_block_position = log.header.data_end;
    iter.block_len = log.data_len - position;
  }
  return sparkey_returncode.SPARKEY_SUCCESS;
}

function logiter_seek(iter, log, position) {
  assert_iter_open(iter, log);
  if(position == log.header.data_end) {
    iter.state = sparkey_iterator_state.SPARKEY_ITER_CLOSED;
    return sparkey_returncode.SPARKEY_SUCCESS;
  }
  let rc = seekblock(iter, log, position);
  if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
    throw new Error(rc);
  }
  // RETHROW(seekblock(iter, log, position));
  iter.entry_count = -1;
  iter.state = sparkey_iterator_state.SPARKEY_ITER_NEW;
  return sparkey_returncode.SPARKEY_SUCCESS;
}

// big int does not have min
function min64(a, b) {
  if(a < b) {
    return a;
  }
  return b;
}

function ensure_available(iter, log) {
  if(iter.block_offset < iter.block_len) {
    return sparkey_returncode.SPARKEY_SUCCESS;
  }
  if(iter.next_block_position >= log.header.data_end) {
    iter.block_position = 0n;
    iter.block_offset = 0n;
    iter.block_len = 0n;
    return sparkey_returncode.SPARKEY_SUCCESS;
  }
  let rc = seekblock(iter, log, iter.next_block_position);
  if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
    return rc;
  }
  iter.entry_count = -1;

  return sparkey_returncode.SPARKEY_SUCCESS;
}

function logiter_skip(iter, log, count) {
  while(count > 0) {
    count--;
    let rc = logiter_next(iter, log);
    if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
      throw new Error(rc);
    }
  }
  return sparkey_returncode.SPARKEY_SUCCESS;
}

function skip(iter, log, len) {
  while (len > 0) {
    let rc = ensure_available(iter, log);
    if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
      throw new Error(`ensure available failed: ${rc}`);
    }
    let m = min64(len, iter.block_len - iter.block_offset);
    len -= m;
    iter.block_offset += m;
  }
  return sparkey_returncode.SPARKEY_SUCCESS;
}

// static inline uint64_t read_vlq(uint8_t * array, uint64_t *position)
// Note we are using a Buffer here rather than an array but otherwise it's the same
// returns an object containing the value of the variable length quantity and the
// new position 
function read_vlq(buffer, position) {
  let res = 0;
  let shift = 0;
  let tmp, tmp2;
  let next_pos;
  while (1) {
    next_pos = position;
    assert_safe_int(next_pos);
    let safe_next_pos = Number(next_pos);
    tmp = buffer[safe_next_pos]; // tmp = buffer[(*position)++];
    next_pos = position + 1n;
    tmp2 = tmp & 0x7f;
    if(tmp == tmp2) {
      return {value: res | tmp << shift, next_pos: next_pos};
    }
    res |= tmp2 << shift;
    shift += 7;
  }
  return {value: res, next_pos: next_pos};
}

function logiter_next(iter, log) {
  if(iter.state == sparkey_iterator_state.SPARKEY_ITER_CLOSED) {
    return sparkey_returncode.SPARKEY_SUCCESS;
  }
  let key_remaining = 0;
  let value_remaining = 0;
  if(iter.state == sparkey_iterator_state.SPARKEY_ITER_ACTIVE) {
    key_remaining = iter.key_remaining;
    value_remaining = iter.value_remaining;
  }

  iter.state = sparkey_iterator_state.SPARKEY_ITER_INVALID;
  iter.key_remaining = 0;
  iter.value_remaining = 0;
  iter.keylen = 0;
  iter.valuelen = 0;
  let rc = undefined;
  rc = assert_iter_open(iter, log);
  if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
    throw new Error(rc);
  }
  rc = skip(iter, log, key_remaining);
  if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
    throw new Error(rc);
  }
  rc = skip(iter, log, value_remaining);
  if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
    throw new Error(rc);
  }
  rc = ensure_available(iter, log);
  if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
    throw new Error(rc);
  }
  if(iter.block_len - iter.block_offset === 0n) {
    // Reached end of data
    iter.state = sparkey_iterator_state.SPARKEY_ITER_CLOSED;
    return sparkey_returncode.SPARKEY_SUCCESS;
  }

  if(log.header.compression_type == sparkey_returncode.SPARKEY_COMPRESSION_NONE) {
  	iter.block_position += iter.block_offset;
  	iter.block_len -= iter.block_offset;
  	iter.block_offset = 0n;
    assert_safe_int(iter.block_position);
    iter.compression_buf = log.data.slice(Number(iter.block_position));
    iter.entry_count = -1;
  }

  iter.entry_count++;

  // printf("block_position %llu block_offset %llu\n", iter->block_position, iter->block_offset);
  // console.log(`${iter.compression_buf.slice(0,10)} off ${iter.block_offset}`);
  // console.log(`buf ${iter.compression_buf} ${iter.block_offset}`);

  // console.log(`block_position ${iter.block_position} block_offset ${iter.block_offset}`);

  let vnp = read_vlq(iter.compression_buf, iter.block_offset);
  
  let a = vnp.value;
  iter.block_offset = vnp.next_pos;

  // console.log(`a ${a}`);

  vnp = read_vlq(iter.compression_buf, iter.block_offset);
  
  let b = vnp.value;
  iter.block_offset = vnp.next_pos;

  // console.log(`b ${b}`);

  if(a === 0) {
    iter.keylen = iter.key_remaining = b;
    iter.valuelen = iter.value_remaining = 0;
    iter.type = sparkey_entry_type.SPARKEY_ENTRY_DELETE;
  } else {
    // console.log(iter);
    iter.keylen = iter.key_remaining = a - 1;
    iter.valuelen = iter.value_remaining = b;
    iter.type = sparkey_entry_type.SPARKEY_ENTRY_PUT;
  }

  iter.entry_block_position = iter.block_position;
  iter.entry_block_offset = iter.block_offset;

  iter.state = sparkey_iterator_state.SPARKEY_ITER_ACTIVE;
  return sparkey_returncode.SPARKEY_SUCCESS;
}


// static sparkey_returncode sparkey_logiter_chunk(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint64_t *len, uint8_t ** res, uint64_t *var) {
//   RETHROW(assert_iter_open(iter, log));

//   if (iter->state != SPARKEY_ITER_ACTIVE) {
//     return SPARKEY_LOG_ITERATOR_INACTIVE;
//   }

//   if (*var > 0) {
//     RETHROW(ensure_available(iter, log));
//     uint64_t m = min64(*var, iter->block_len - iter->block_offset);
//     m = min64(maxlen, m);
//     *len = m;
//     *res = &iter->compression_buf[iter->block_offset];
//     iter->block_offset += m;
//     *var -= m;
//     return SPARKEY_SUCCESS;
//   }
//   *len = 0;
//   return SPARKEY_SUCCESS;
// }

// sparkey_returncode sparkey_logiter_keychunk(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint8_t ** res, uint64_t *len) {
//   return sparkey_logiter_chunk(iter, log, maxlen, len, res, &iter->key_remaining);
// }
// static sparkey_returncode sparkey_logiter_chunk(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint64_t *len, uint8_t ** res, uint64_t *var) {
// Returns an object {rc: [return code], chunk_buffer: [Buffer containing the chunk], chunk_length: [length of the chunk], chunk_remain: [chunk remaining]} 
// In the original code
//   var tracks the remaining key/value length (chunk)
//   res will be a buffer pointing to the data
//   len is the length of res
function logiter_chunk(iter, log, maxlen, chunk_remaining) {
  assert_iter_open(iter, log);

  let maxlen_big = BigInt(maxlen);
  let chunk_length = 0n;

  if(iter.state != sparkey_iterator_state.SPARKEY_ITER_ACTIVE) {
    return {rc: sparkey_returncode.SPARKEY_LOG_ITERATOR_INACTIVE};
  }

  if(chunk_remaining > 0n) {
    let rc = ensure_available(iter, log);
    if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
      return {rc: rc};
    }
    let m = min64(chunk_remaining, iter.block_len - iter.block_offset);
    m = min64(maxlen_big, m);
          // console.log(`m ${m} ${typeof m}`);
          // console.log(`chunk_length ${chunk_length} ${typeof chunk_length}`);
          // console.log(`chunk_remaining ${chunk_remaining} ${typeof chunk_remaining}`);
    chunk_length = m;
    assert_safe_int(iter.block_offset);

    let buffer = iter.compression_buf.slice(Number(iter.block_offset));
    iter.block_offset += m;
    chunk_remaining -= m;
    return {
      rc: sparkey_returncode.SPARKEY_SUCCESS,
      buffer: buffer,
      chunk_remaining: chunk_remaining,
      chunk_length: chunk_length
    };
  }

  return {
    rc: sparkey_returncode.SPARKEY_SUCCESS,
    chunk_length: 0
  };
}

// sparkey_returncode sparkey_logiter_keychunk(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint8_t ** res, uint64_t *len) {
//   return sparkey_logiter_chunk(iter, log, maxlen, len, res, &iter->key_remaining);
// }
// log iterator, a log, max len of returned data, res is the memory we want the result in, len is where to store the length of the key
// Returns an object {rc: [return code], chunk_buffer: [Buffer containing the chunk], chunk_length: [length of the chunk]} 
function logiter_keychunk(iter, log, maxlen) {
  return logiter_chunk(iter, log, maxlen, BigInt(iter.key_remaining));
}

function logiter_valuechunk(iter, log, maxlen) {
  return logiter_chunk(iter, log, maxlen, BigInt(iter.value_remaining));
}

// static inline uint64_t get_displacement(uint64_t capacity, uint64_t slot, uint64_t hash) {
//   uint64_t wanted_slot = hash % capacity;
//   return (capacity + (slot - wanted_slot)) % capacity;
// }
// note everything is bigint here
function get_displacement(capacity, slot, hash) {
  let wanted_slot = hash % capacity;
  return (capacity + (slot - wanted_slot)) % capacity;
}

// TODO does need to be async?
// Probably not because file operations are hidden by the mmap and are
// blocking anyway
function get(reader, log_iterator, lookupKeyBuf, keyBuffer, valueBuffer) {
  let keylen = lookupKeyBuf.length
  if(reader.open_status !== MAGIC_VALUE_HASHREADER) {
    throw new Error("Hash reader is not open");
  }
  let hash = BigInt(reader.header.hash_algorithm(lookupKeyBuf, reader.header.hash_seed));

  // uint64_t wanted_slot = hash % reader->header.hash_capacity;
  let wanted_slot = BigInt(hash) % reader.header.hash_capacity;
  slot_size = BigInt(reader.header.address_size + reader.header.hash_size);
  pos = wanted_slot * slot_size;

  let displacement = 0;
  slot = wanted_slot;

  hashtable = reader.data.slice(reader.header.header_size);

  while(1) {
    let hash2 = read_hash(hashtable, pos, reader.header.hash_size); 
    position2 = read_addr(hashtable, pos + BigInt(reader.header.hash_size), reader.header.address_size);
    // console.log(`hashes ${hash} hash2 ${hash2} position2 ${position2}`);
    if(position2 === 0n) {
      console.log('not found');
      log_iterator.state = 'SPARKEY_ITER_INVALID';
      return sparkey_returncode.SPARKEY_SUCCESS;
    }
    let entry_index2 = position2 & BigInt(reader.header.entry_block_bitmask);
    // console.log(`entry_index2 ${entry_index2}`);
    position2 = position2 >> BigInt(reader.header.entry_block_bits);
    if(hash === hash2) {
      let rc = undefined;
  //     RETHROW(sparkey_logiter_seek(iter, &reader.log, position2));
      rc = logiter_seek(log_iterator, reader.log, position2);
      if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
        throw new Error(rc);
      }
  //     RETHROW(sparkey_logiter_skip(iter, &reader.log, entry_index2));
      rc = logiter_skip(log_iterator, reader.log, entry_index2);
      if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
        throw new Error(rc);
      }
  //     RETHROW(sparkey_logiter_next(iter, &reader.log));
      // TODO should be checking the ret codes here, just implement RETHROW
      rc = logiter_next(log_iterator, reader.log);
      if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
        throw new Error(rc);
      }
      let keylen2 = log_iterator.keylen;
      // Sanity check it is a put not a delete entry
      if(log_iterator.type !== sparkey_entry_type.SPARKEY_ENTRY_PUT) {
        log_iterator.state = sparkey_iterator_state.SPARKEY_ITER_INVALID;
        return sparkey_returncode.SPARKEY_INTERNAL_ERROR;
      }
      // console.log(`key lengths ${keylen} ${keylen2}`);
      if (keylen == keylen2) {
        let pos2 = 0n;
        let equals = 1;
        // To ensure there is an actual match and no collision we need to compare the key
        while (pos2 < keylen) {
          // console.log(pos2);
          // uint8_t *buf2;
          // uint64_t len2;
          // RETHROW(sparkey_logiter_keychunk(iter, &reader.log, keylen, &buf2, &len2));
          let result = logiter_keychunk(log_iterator, reader.log, keylen); 
          // TODO compare the buffer as it is copied
          // this relies on passing a buffer as the key lookup though so i'll do later
          // if (memcmp(&key[pos2], buf2, len2) != 0) {
          //   equals = 0;
          //   break;
          // }
          if(result.rc !== sparkey_returncode.SPARKEY_SUCCESS) {
            console.log(`keychunk failed with rc ${result.rc}`);
            return result.rc;
          }
          // console.log('copying key chunk');
          // console.log(JSON.stringify(result));
          // console.log(`pos2 ${typeof pos2} ${pos2}`);

          result.buffer.copy(keyBuffer,Number(pos2),0,Number(result.chunk_length));
          // console.log(`key from log file ${keyBuffer.toString()}`);

          pos2 += result.chunk_length;
        }
        if(equals) {
          if(log_iterator.state === sparkey_iterator_state.SPARKEY_ITER_ACTIVE) {

            let result;
            let pos = 0n;
            do {
              result = logiter_valuechunk(log_iterator, reader.log, reader.log.header.max_value_len);
              result.buffer.copy(valueBuffer,Number(0),Number(pos),Number(result.chunk_length));
              pos += result.chunk_length;
            } while(result.chunk_remaining > 0n);
          }

          return sparkey_returncode.SPARKEY_SUCCESS;
        }
        // otherwise it wasn't a match keep going
      }
      return sparkey_returncode.SPARKEY_SUCCESS;
    }
    let other_displacement = get_displacement(reader.header.hash_capacity, slot, hash2);
    if (displacement > other_displacement) {
      iter.state === SPARKEY_ITER_INVALID;
      return sparkey_returncode.SPARKEY_SUCCESS;
    }
    pos += slot_size;
    displacement++;
    slot++;
    if (slot >= reader.header.hash_capacity) {
      pos = 0;
      slot = 0;
    }
  }
  log_iterator.state = sparkey_iterator_state.SPARKEY_ITER_INVALID;
  return sparkey_returncode.SPARKEY_INTERNAL_ERROR;
}
async function closeHash(reader) {
  await closeLog(reader.log);
  reader.log = null;
  reader.open_status = null;
}

function logiter_create(log) {
  assert_log_open(log);

  let iter = {};
  iter.open_status = MAGIC_VALUE_LOGITER;
  iter.file_identifier = log.header.file_identifier;
  iter.block_position = 0n;
  iter.next_block_position = log.header.header_size;
  iter.block_offset = 0n;
  iter.block_len = 0n;
  iter.state = sparkey_iterator_state.SPARKEY_ITER_NEW;

  if(log.header.compression_type !== sparkey_compression_type.SPARKEY_COMPRESSION_NONE) {
    throw new Error('Block compression not implemented');
    // iter.compression_buf_allocated = 1;
    // iter.compression_buf = malloc(log.header.compression_block_size);
    // if (iter.compression_buf == NULL) {
    //   free(iter);
    //   return SPARKEY_INTERNAL_ERROR;
    // }
  } else {
    iter.compression_buf_allocated = 0;
  }

  return iter;
}

function logiter_close(iter) {
  if(iter.open_status !== MAGIC_VALUE_LOGITER) {
    return;
  }
  iter.open_status = 0;

  // Probably not needed if you implement compression, the decompression will go into a Block
  // and that can be simply garbage collected when the log iterator goes out of scope.
  // if(iter.compression_buf_allocated) {
  //   free(iter.compression_buf);
  // }
}

async function run() {
  const sampleIndexFile = 'SampleLog1.spi';
  const sampleLogFile = 'SampleLog1.spl';

  try {
    let hashReader = await openHash(sampleIndexFile, sampleLogFile);

    console.log(`Opened hash file ${sampleIndexFile} with id ${hashReader.header.file_identifier}`);

    // Need a log iterator
    let logIterator = logiter_create(hashReader.log);

    // Create buffers for retrieved key and values
    let keyBuffer = Buffer.alloc(Number(hashReader.log.header.max_key_len));
    let valueBuffer = Buffer.alloc(Number(hashReader.log.header.max_value_len));

    let lookupKeys = [1,2,3,1].map(i => "key" + i).map(Buffer.from);
    // console.log(JSON.stringify(logIterator));

    // lookup each key
    lookupKeys.forEach(lookupKeyBuf => {
      console.log(`lookup ${lookupKeyBuf.toString()}`);
      get(hashReader, logIterator, lookupKeyBuf, keyBuffer, valueBuffer);
      console.log(valueBuffer.toString());
    });

    logiter_close(logIterator);

    await closeHash(hashReader);
  } catch (e) {
    console.log(e.message);
  };
};
run();
