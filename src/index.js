const fs = require('fs').promises;
const mhn = require('murmurhash-native');

const HASH_MAGIC_NUMBER = 0x9a11318f;
const HASH_MAJOR_VERSION = 1;
const HASH_MINOR_VERSION = 1;
const HASH_HEADER_SIZE= 112;

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
