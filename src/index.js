import { promises as fs } from 'fs';
import mhn from 'murmurhash-native';
import { MMapping } from 'great-big-file-reader';
import buffer from 'buffer';

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
// eslint-disable-next-line no-unused-vars
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

function murmurHash64BigInt(keyBuffer, seed) {
  return BigInt('0x' + mhn.murmurHash64(keyBuffer,seed));
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
    h.hash_algorithm = murmurHash64BigInt;
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
  await fileHandle.close();
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

  log.mmapping = new MMapping(log_file_path, fd.fd);

  if(!error) {
    log.fd = fd;
    // log.data = mmap.map(Number(log.data_len), mmap.PROT_READ, mmap.MAP_SHARED, log.fd.fd);
    // TODO Note this won't work with large files so we may need something more to describe the current window
    //   note that log.data is assuming the whole thing is a buffer which we cannot do 
    // log.data = log.mmapping.getBuffer(0n, log.data_len);
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
  log.mmapping.unmap();
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

  if(error) {
    throw new Error(error);
  }

  reader.fd = await fs.open(index_file_path, 'r');
  let stats = await reader.fd.stat();

  reader.data_len = BigInt(reader.header.header_size) + reader.header.hash_capacity * 
                    (BigInt(reader.header.hash_size) + BigInt(reader.header.address_size));

  if(reader.data_len > stats.size) {
    error = "SPARKEY_LOG_TOO_SMALL";
  } 

  reader.mmapping = new MMapping(index_file_path, reader.fd.fd);

  // reader.data = mmap.map(Number(reader.data_len), mmap.PROT_READ, mmap.MAP_SHARED, reader.fd.fd);

  // reader.data = reader.mmapping.getBuffer(0n, reader.data_len);
  reader.open_status = MAGIC_VALUE_HASHREADER;

  return reader;
}

function read_from_hash(rdr, pos, size) {
  let bigSize = BigInt(size);
  let adjusted_pos = pos - rdr.buffer_start;  
  if(adjusted_pos < 0n)  { // before window
    rdr.buffer_start = rdr.buffer_start + adjusted_pos;
    rdr.buffer_length = rdr.max_buffer;
    if(rdr.buffer_start + rdr.buffer_length > rdr.data_len) {
      rdr.buffer_length = rdr.data_len - rdr.buffer_start;
    }
    rdr.buffer = rdr.mmapping.getBuffer(rdr.buffer_start + BigInt(rdr.header.header_size), rdr.buffer_length);
    adjusted_pos = 0n;
  } else if(adjusted_pos + bigSize > rdr.buffer_length) {
    rdr.buffer_start = pos;
    rdr.buffer_length = rdr.max_buffer;
    if(rdr.buffer_start + rdr.buffer_length > rdr.data_len) {
      rdr.buffer_length = rdr.data_len - rdr.buffer_start;
    }
    rdr.buffer = rdr.mmapping.getBuffer(rdr.buffer_start + BigInt(rdr.header.header_size), rdr.buffer_length);
    adjusted_pos = 0n;
  }
  let offset = Number(adjusted_pos);
  // assert_safe_int(pos);
  switch (bigSize) {
    case 4n: return BigInt(rdr.buffer.readUint32LE(offset));
    case 8n: return rdr.buffer.readBigUint64LE(offset);
  }
  throw new Error(`Unsupported size ${bigSize}`)
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
    // Max buffer we care about is max key length plus max max value length plus the max size of the two vlqs
    let max_buffer = log.header.max_key_len + log.header.max_value_len + 128n;
    let buffer_size = min64(max_buffer, log.data_len - position);
    iter.compression_buf = log.mmapping.getBuffer(position, buffer_size);
    // iter.compression_buf = log.data.slice(Number(position));
    iter.block_position = position;
    iter.next_block_position = log.header.data_end;
    iter.block_len = log.data_len - position;
  }
  return sparkey_returncode.SPARKEY_SUCCESS;
}

function logiter_seek(iter, log, position) {
  assert_iter_open(iter, log);
  if(position === log.header.data_end) {
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

function skip(iter, log, lenNumber) {
  let len = BigInt(lenNumber);
  while (len > 0n) {
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
  while(true) { // eslint-disable-line no-constant-condition
    next_pos = position;
    assert_safe_int(next_pos);
    let safe_next_pos = Number(next_pos);
    tmp = buffer[safe_next_pos];
    next_pos = position + 1n;
    tmp2 = tmp & 0x7f;
    if(tmp === tmp2) {
      return {value: res | tmp << shift, next_pos: next_pos};
    }
    res |= tmp2 << shift;
    shift += 7;
  }
}

function logiter_next(iter, log) {
  if(iter.state === sparkey_iterator_state.SPARKEY_ITER_CLOSED) {
    return sparkey_returncode.SPARKEY_SUCCESS;
  }
  let key_remaining = 0;
  let value_remaining = 0;
  if(iter.state === sparkey_iterator_state.SPARKEY_ITER_ACTIVE) {
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

  if(log.header.compression_type === sparkey_compression_type.SPARKEY_COMPRESSION_NONE) {
    iter.block_position += iter.block_offset;
    iter.block_len -= iter.block_offset;
    iter.block_offset = 0n;

    let max_buffer = log.header.max_key_len + log.header.max_value_len + 128n;
    let buffer_size = min64(max_buffer, log.data_len - iter.block_position);
    iter.compression_buf = log.mmapping.getBuffer(iter.block_position, buffer_size);
    // iter.compression_buf = log.data.slice(Number(iter.block_position));
    iter.entry_count = -1;
  } else {
    throw new Error('Compression type not supported');
  }

  iter.entry_count++;

  let vnp = read_vlq(iter.compression_buf, iter.block_offset);
  
  let a = vnp.value;
  iter.block_offset = vnp.next_pos;

  vnp = read_vlq(iter.compression_buf, iter.block_offset);
  
  let b = vnp.value;
  iter.block_offset = vnp.next_pos;

  // Each entry begins with two Variable Length Quantity (VLQ) non-negative integers, A and B. The type
  // is determined by the A. If A = 0, it's a DELETE, and B represents the length of the key to delete.
  // If A > 0, it's a PUT and the key length is A - 1, and the value length is B.

  if(a === 0) {
    iter.keylen = iter.key_remaining = b;
    iter.valuelen = iter.value_remaining = 0;
    iter.type = sparkey_entry_type.SPARKEY_ENTRY_DELETE;
  } else {
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
// Returns this object
// {found: boolean, length: if found is the length of the value in the value buffer}
function get(reader, log_iterator, lookupKeyBuf, valueBuffer) {
  let keylen = lookupKeyBuf.length
  if(reader.open_status !== MAGIC_VALUE_HASHREADER) {
    throw new Error("Hash reader is not open");
  }
  let hash = BigInt(reader.header.hash_algorithm(lookupKeyBuf, reader.header.hash_seed));

  let wanted_slot = BigInt(hash) % reader.header.hash_capacity;
  let slot_size = BigInt(reader.header.address_size + reader.header.hash_size);
  let pos = wanted_slot * slot_size;

  let displacement = 0n;
  let slot = wanted_slot;

  while(true) { // eslint-disable-line no-constant-condition
    let hash2 = read_from_hash(reader, pos, reader.header.hash_size); 
    let position2 = read_from_hash(reader, pos + BigInt(reader.header.hash_size), reader.header.address_size);
    console.log(`hashes ${hash} hash2 ${hash2} position2 ${position2}`);
    if(position2 === 0n) {
      // console.log('not found, end of hash table');
      log_iterator.state = 'SPARKEY_ITER_INVALID';
      return {
        found: false,
        length: 0
      };
    }
    let entry_index2 = position2 & BigInt(reader.header.entry_block_bitmask);
    console.log(`entry_index2 ${entry_index2}`);
    position2 = position2 >> BigInt(reader.header.entry_block_bits);
    if(hash === hash2) {
      let rc = undefined;
  //     RETHROW(sparkey_logiter_seek(iter, &reader.log, position2));
      console.log('seek ' + position2);
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
        throw new Error(sparkey_returncode.SPARKEY_INTERNAL_ERROR);
      }
      // console.log(`key lengths ${keylen} ${keylen2}`);
      if (keylen === keylen2) {
        let pos2 = 0n;
        let equals = true;
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
            throw new Error(result.rc);
          }

          // Compare this chunk of the key with the search key since hash collisions
          // may occur
          // buf.compare(target[, targetStart[, targetEnd[, sourceStart[, sourceEnd]]]])
          if(lookupKeyBuf.compare(result.buffer,0,Number(result.chunk_length - 1n),Number(pos2),Number(pos2 + result.chunk_length - 1n))
            !== 0) {
            // console.log('key not equals');
            equals = false;
          }
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
            assert_safe_int(pos);
            return {
              found: true,
              length: Number(pos)
            };
          }
        }
      }
    }
    let other_displacement = get_displacement(reader.header.hash_capacity, slot, hash2);
    if (displacement > other_displacement) {
      log_iterator.state === sparkey_iterator_state.SPARKEY_ITER_INVALID;
      // console.log('return not found displacement');
      return {found: false, length: 0};
    }
    pos += slot_size;
    displacement++;
    slot++;
    if (slot >= reader.header.hash_capacity) {
      pos = 0n;
      slot = 0n;
    }
  }
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
  iter.next_block_position = BigInt(log.header.header_size);
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
  const sparkeyPath = '/Users/justin.heyes-jones/projects/lantern/build/';
  const sparkeyTable = 'sparkey100million';

  const sampleIndexFile = sparkeyPath + sparkeyTable + '.spi';
  const sampleLogFile = sparkeyPath + sparkeyTable + '.spl';
  const keysFile = sparkeyPath + sparkeyTable + '.csv';

  try {
    const keyFileContents = await fs.readFile(keysFile, 'utf-8');
    const lookupKeys = keyFileContents.split('\n').filter(k => k.length > 0).map(k => Buffer.from(k));

    let hashReader = await openHash(sampleIndexFile, sampleLogFile);

    console.log(`Opened hash file ${sampleIndexFile} with id ${hashReader.header.file_identifier}`);

    // Need a log iterator
    let logIterator = logiter_create(hashReader.log);

    var iterate_example = false;
    var get_example = true;

    if(iterate_example) {
      let count = 0;
      let stride = 100000;
      while(true) {// eslint-disable-line no-constant-condition
        let rc = logiter_next(logIterator, hashReader.log);
        if(rc !== sparkey_returncode.SPARKEY_SUCCESS || logIterator.state != sparkey_iterator_state.SPARKEY_ITER_ACTIVE) {
          break;
        }
        count ++;
        // console.log(`${count} ${logIterator.block_offset} ${logIterator.block_position}`);

        let bo = logIterator.block_offset;

        let key_result = logiter_keychunk(logIterator, hashReader.log, hashReader.log.header.max_key_len); 
        let k = key_result.buffer.slice(0,Number(key_result.chunk_length)).toString();

        let value_result = logiter_valuechunk(logIterator, hashReader.log, hashReader.log.header.max_value_len);
        let v = value_result.buffer.slice(0,Number(value_result.chunk_length)).toString();

        if(count % stride == 0) {
          console.log(`Key: ${k} Value: ${v}`);
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
        let result = get(hashReader, logIterator, lookupKeyBuf, valueBuffer);
        if(result.found) {
          found += 1;
          // console.log(valueBuffer.slice(0, result.length).toString() + result.length);
        } else {
          not_found += 1;
        }
      });

      console.timeEnd('lookups');
      console.log(`found count ${found}, not found count ${not_found}`);
    }

    logiter_close(logIterator);
    await closeHash(hashReader);
  } catch (e) {
    console.log(e.message);
  }
}
run();
