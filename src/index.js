const fs = require('fs').promises;
const mhn = require('murmurhash-native');

const HASH_MAGIC_NUMBER = 0x9a11318f;
const HASH_MAJOR_VERSION = 1;
const HASH_MINOR_VERSION = 1;
const HASH_HEADER_SIZE= 112;

BigInt.prototype.toJSON = function() { return this.toString() }

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

  await fileHandle.read(readBuffer, 0, 4);
  h.file_identifier = readBuffer.readUint32LE(0);
  await fileHandle.read(readBuffer, 0, 4);
  h.hash_seed = readBuffer.readUint32LE(0);
  await fileHandle.read(readBuffer, 0, 8);
  h.data_end = readBuffer.readBigUint64LE(0);
  await fileHandle.read(readBuffer, 0, 8);
  h.max_key_len = readBuffer.readBigUint64LE(0);
  await fileHandle.read(readBuffer, 0, 8);
  h.max_value_len = readBuffer.readBigUint64LE(0);
  await fileHandle.read(readBuffer, 0, 8);
  h.num_puts = readBuffer.readBigUint64LE(0);
  await fileHandle.read(readBuffer, 0, 8);
  h.garbage_size = readBuffer.readBigUint64LE(0);
  await fileHandle.read(readBuffer, 0, 8);
  h.num_entries = readBuffer.readBigUint64LE(0);

  // RETHROW(fread_little_endian32(fp, &header->address_size));
  // RETHROW(fread_little_endian32(fp, &header->hash_size));
  // RETHROW(fread_little_endian64(fp, &header->hash_capacity));
  // RETHROW(fread_little_endian64(fp, &header->max_displacement));
  // RETHROW(fread_little_endian32(fp, &header->entry_block_bits));
  // header->entry_block_bitmask = (1 << header->entry_block_bits) - 1;
  // RETHROW(fread_little_endian64(fp, &header->hash_collisions));
  // RETHROW(fread_little_endian64(fp, &header->total_displacement));
  // header->header_size = HASH_HEADER_SIZE;

  // header->hash_algorithm = sparkey_get_hash_algorithm(header->hash_size);
  // if (header->hash_algorithm.hash == NULL) {
  //   return SPARKEY_HASH_HEADER_CORRUPT;
  // }
  // // Some basic consistency checks
  // if (header->num_entries > header->num_puts) {
  //   return SPARKEY_HASH_HEADER_CORRUPT;
  // }
  // if (header->max_displacement > header->num_entries) {
  //   return SPARKEY_HASH_HEADER_CORRUPT;
  // }
  // if (header->hash_collisions > header->num_entries) {
  //   return SPARKEY_HASH_HEADER_CORRUPT;
  // }

  // return SPARKEY_SUCCESS;

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
