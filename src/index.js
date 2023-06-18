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

BigInt.prototype.toJSON = function() { return this.toString() }

function bigIntToNumberDivision(dividend, divisor) {
  return Number(dividend*1000n/divisor)/1000.0;
}

async function readUint32(fp, buf) {
  await fp.read(buf, 0, 4);
  return buf.readUint32LE(0);
}

async function readUint64(fp, buf) {
  await fp.read(buf, 0, 8);
  return buf.readBigUint64LE(0);
}

// Some of Sparkey code base uses 64 bit numbers
function assert_safe_int(num) {
  let converted = Number(num);
  if(!Number.isSafeInteger(converted)) {
    throw new Error(`${num} to large to be used as an integer`)
  }
}

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

async function loadHashHeader(index_file_path) {
  const fileHandle = await fs.open(index_file_path, 'r');
  const readBuffer = Buffer.alloc(8);
  await fileHandle.read(readBuffer, 0, 4);

  const magicNumber = readBuffer.readUInt32LE(0);
  if (magicNumber !== HASH_MAGIC_NUMBER) {
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
  if (h.max_displacement > h.num_entries) {
    throw new Error("SPARKEY_HASH_HEADER_CORRUPT");
  }
  if (h.hash_collisions > h.num_entries) {
    throw new Error("SPARKEY_HASH_HEADER_CORRUPT");
  }

  await fileHandle.close();
  return h;
}

async function loadLogHeader(log_file_path) {
  const fileHandle = await fs.open(log_file_path, 'r');
  const readBuffer = Buffer.alloc(8);
  await fileHandle.read(readBuffer, 0, 4);

  const magicNumber = readBuffer.readUInt32LE(0);
  if (magicNumber !== LOG_MAGIC_NUMBER) {
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
  if (h.data_end < h.header_size) {
    throw new Error("SPARKEY_LOG_HEADER_CORRUPT");
  }
  if (h.num_puts > h.data_end) {
    throw new Error("SPARKEY_LOG_HEADER_CORRUPT");
  }
  if (h.num_deletes > h.data_end) {
    throw new Error("SPARKEY_LOG_HEADER_CORRUPT");
  }
  if (h.compression_type > sparkey_compression_type.SPARKEY_COMPRESSION_ZSTD) {
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
    fd.close();
    throw new Error(error);
  }

  return log;
}

async function closeLog(log) {
  log.fd.close();
  log.fd = null;
}

async function openHash(index_file_path, log_file_path) {
  let reader = {};
  reader.header = await loadHashHeader(index_file_path); 
  // console.log(hashHeaderToString(reader.header));
  reader.log = await openLog(log_file_path); 

  let error = null;

  if (reader.header.file_identifier != reader.log.header.file_identifier) {
    error = "SPARKEY_FILE_IDENTIFIER_MISMATCH";
  }
  else if (reader.header.data_end > reader.log.header.data_end) {
    error = "SPARKEY_HASH_HEADER_CORRUPT";
  }
  else if (reader.header.max_key_len > reader.log.header.max_key_len) {
    error = "SPARKEY_HASH_HEADER_CORRUPT";
  }
  else if (reader.header.max_value_len > reader.log.header.max_value_len) {
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
  if (log.open_status !== MAGIC_VALUE_LOGREADER) {
    throw new Error('SPARKEY_LOG_CLOSED');
  }
}

function assert_iter_open(iter, log) {
  assert_log_open(log);
  console.log(iter.open_status);
  if(iter.open_status !== MAGIC_VALUE_LOGITER) {
    throw new Error('SPARKEY_LOG_ITERATOR_CLOSED');
  }
  if (iter.file_identifier !== log.header.file_identifier) {
    throw new Error('SPARKEY_LOG_ITERATOR_MISMATCH');
  }
}

function seekblock(iter, log, position) {
  iter.block_offset = 0;
  if (iter.block_position === position) {
    return SPARKEY_SUCCESS;
  }
  if (log.header.compression_type !== sparkey_compression_type.SPARKEY_COMPRESSION_NONE) {
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
  console.log("seek");
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
  if (a < b) {
    return a;
  }
  return b;
}

function ensure_available(iter, log) {
  if (iter.block_offset < iter.block_len) {
    return sparkey_returncode.SPARKEY_SUCCESS;
  }

  if (iter.next_block_position >= log.header.data_end) {
    iter.block_position = 0;
    iter.block_offset = 0;
    iter.block_len = 0;
    return sparkey_returncode.SPARKEY_SUCCESS;
  }
  let rc = seekblock(iter, log, iter.next_block_position);
  if(rc !== sparkey_returncode.SPARKEY_SUCCESS) {
    throw new Error(rc);
  }
  iter.entry_count = -1;

  return sparkey_returncode.SPARKEY_SUCCESS;
}

function logiter_skip(iter, log, len) {
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

function logiter_next(iter, log) {

  // TODO 
}

async function get(reader, key_string, log_iterator) {
  console.log(`hash_get ${key_string}`)
  if(reader.open_status !== MAGIC_VALUE_HASHREADER) {
    throw new Error("Hash reader is not open");
  }
  let hash = BigInt(reader.header.hash_algorithm(key_string, reader.header.hash_seed));

  // uint64_t wanted_slot = hash % reader->header.hash_capacity;
  let wanted_slot = BigInt(hash) % reader.header.hash_capacity;
  slot_size = BigInt(reader.header.address_size + reader.header.hash_size);
  pos = wanted_slot * slot_size;

  displacement = 0;
  slot = wanted_slot;

  hashtable = reader.data.slice(reader.header.header_size);

  {
  // while(1) {
    let hash2 = read_hash(hashtable, pos, reader.header.hash_size); 
    position2 = read_addr(hashtable, pos + BigInt(reader.header.hash_size), reader.header.address_size);
    if (position2 === 0n) {
      console.log('not found');
      log_iterator.state = 'SPARKEY_ITER_INVALID';
      return 'SPARKEY_SUCCESS';
    }
    let entry_index2 = position2 & BigInt(reader.header.entry_block_bitmask);
    position2 = position2 >> BigInt(reader.header.entry_block_bits);
    if (hash === hash2) {
  //     RETHROW(sparkey_logiter_seek(iter, &reader.log, position2));
      logiter_seek(log_iterator, reader.log, position2);
  //     RETHROW(sparkey_logiter_skip(iter, &reader.log, entry_index2));
      logiter_skip(log_iterator, reader.log, entry_index2);
  //     RETHROW(sparkey_logiter_next(iter, &reader.log));
      // TODO should be checking the ret codes here, just implement RETHROW
      logiter_next(log_iterator, reader.log);
  //     uint64_t keylen2 = iter.keylen;
  //     // Saninty check it is a put not a delete entry
  //     if (iter.type != SPARKEY_ENTRY_PUT) {
  //       iter.state = SPARKEY_ITER_INVALID;
  //       return SPARKEY_INTERNAL_ERROR;
  //     }
  //     if (keylen == keylen2) {
  //       uint64_t pos2 = 0;
  //       int equals = 1;
  //       while (pos2 < keylen) {
  //         uint8_t *buf2;
  //         uint64_t len2;
  //         RETHROW(sparkey_logiter_keychunk(iter, &reader.log, keylen, &buf2, &len2));
  //         if (memcmp(&key[pos2], buf2, len2) != 0) {
  //           equals = 0;
  //           break;
  //         }
  //         pos2 += len2;
  //       }
  //       if (equals) {
  //         return SPARKEY_SUCCESS;
  //       }
  //     }
      return 'SPARKEY_SUCCESS';
    }
  //   uint64_t other_displacement = get_displacement(reader.header.hash_capacity, slot, hash2);
  //   if (displacement > other_displacement) {
  //     iter.state = SPARKEY_ITER_INVALID;
  //     return SPARKEY_SUCCESS;
  //   }
  //   pos += slot_size;
  //   displacement++;
  //   slot++;
  //   if (slot >= reader.header.hash_capacity) {
  //     pos = 0;
  //     slot = 0;
  }
  log_iterator.state = 'SPARKEY_ITER_INVALID';
  return 'SPARKEY_INTERNAL_ERROR';
}
async function closeHash(reader) {
  closeLog(reader.log);
  reader.log = null;
  reader.open_status = null;
}

function logiter_create(log) {
  assert_log_open(log);

  let iter = {};
  iter.open_status = MAGIC_VALUE_LOGITER;
  iter.file_identifier = log.header.file_identifier;
  iter.block_position = 0;
  iter.next_block_position = log.header.header_size;
  iter.block_offset = 0;
  iter.block_len = 0;
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

function sparkey_logiter_close(iter) {
  if (iter == NULL) {
    return;
  }
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
  const sampleIndexFile = 'testdata/SampleLog1.spi';
  const sampleLogFile = 'testdata/SampleLog1.spl';

  try {
    let hashReader = await openHash(sampleIndexFile, sampleLogFile);

    // Need a log iterator
    let logIterator = logiter_create(hashReader.log);

    // Can now do lookups
    let getResult1 = await get(hashReader, "key1", logIterator);
    let getResult2 = await get(hashReader, "key2", logIterator);
    let getResult3 = await get(hashReader, "key3", logIterator);

    await closeHash(hashReader);
  } catch (e) {
    console.log(e.message);
  };
};
run();
