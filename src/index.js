const fs = require('fs').promises;
const mhn = require('murmurhash-native');

const HASH_MAGIC_NUMBER = 0x9a11318f;
const HASH_MAJOR_VERSION = 1;
const HASH_MINOR_VERSION = 1;
const HASH_HEADER_SIZE= 112;

BigInt.prototype.toJSON = function() { return this.toString() }

async function readUint32(fp, buf) {
  await fp.read(buf, 0, 4);
  return buf.readUint32LE(0);
}

async function readUint64(fp, buf) {
  await fp.read(buf, 0, 8);
  return buf.readBigUint64LE(0);
}

async function loadHashHeader(index_file_path) {
  const fileHandle = await fs.open(index_file_path, 'r');
  const readBuffer = Buffer.alloc(8);
  await fileHandle.read(readBuffer, 0, 4);

  const magicNumber = readBuffer.readUInt32LE(0);
  if (magicNumber !== HASH_MAGIC_NUMBER) {
    throw new Error('Invalid magic number');
  } else {
    console.log('Magic number checks out!');
  }
  let h = {};
  await fileHandle.read(readBuffer, 0, 8);
  let majorVersion = readBuffer.readUint32LE(0);
  let minorVersion = readBuffer.readUint32LE(4);

  if(majorVersion != HASH_MAJOR_VERSION || minorVersion != HASH_MINOR_VERSION) {
    throw new Error(`Hash file version mismatch. File version ${majorVersion}.${minorVersion} does not match ${HASH_MAJOR_VERSION}.${HASH_MINOR_VERSION}`);
  }

  h.majorVersion = majorVersion;
  h.minorVersion = minorVersion;

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

async function run() {
  const sampleLogFile = 'testdata/SampleLog1.spl';
  const sampleIndexFile = 'testdata/SampleLog1.spi';

  try {
    const header = await loadHashHeader(sampleIndexFile);
    console.log(JSON.stringify(header));
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
