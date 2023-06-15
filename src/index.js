const fs = require('fs').promises;
const mhn = require('murmurhash-native');

const HASH_MAGIC_NUMBER = 0x9a11318f;
const HASH_MAJOR_VERSION = 1;
const HASH_MINOR_VERSION = 1;
const HASH_HEADER_SIZE= 112;

const LOG_MAGIC_NUMBER = 0x49b39c95;
const LOG_MAJOR_VERSION = 1;
const LOG_MINOR_VERSION = 0;
const LOG_HEADER_SIZE = 84;

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

  if(majorVersion != LOG_MAJOR_VERSION || minorVersion > LOG_MAJOR_VERSION) {
    throw new Error(`Log file version mismatch. File version ${majorVersion}.${minorVersion} does not match ${LOG_MAJOR_VERSION}.${LOG_MAJOR_VERSION}`);
  }

  h.major_version = majorVersion;
  h.minor_version = minorVersion;

  console.log(JSON.stringify(h));
  return h;
}

async function openHash(index_file_path, log_file_path) {
  let reader = {};
  reader.header = await loadHashHeader(index_file_path); 
  console.log(hashHeaderToString(reader.header));
  reader.log = await loadLogHeader(log_file_path);

  return true;
}

async function closeHash(reader) {
  // TODO get the index file handle and close it 
}

async function run() {
  const sampleIndexFile = 'testdata/SampleLog1.spi';
  const sampleLogFile = 'testdata/SampleLog1.spl';

  try {
    await openHash(sampleIndexFile, sampleLogFile);
  } catch (e) {
    console.log(e.message);
  };
};

// native murmur hash
  // // 32-bit hash
  // const hash32 = mhn.murmurHash32('hello world');
  // // 64-bit hash
  // const hash64 = mhn.murmurHash64('hello world');
  // console.log(hash32 + " " + hash64);


run();
