const fs = require('fs');
const mmap = require('mmap-utils');

let filepath13gb = '/Users/justin.heyes-jones/projects/lantern/build/sparkey100million.spl';
let filepath4gb = '/Users/justin.heyes-jones/projects/lantern/build/sparkey100million.spi';

let fp = filepath13gb;

const fileDescriptor = fs.openSync(fp, 'r');
const stats = fs.statSync(fp);
const fileSizeInBytes = stats.size;

console.log(fileSizeInBytes); // File size in bytes

const buffer = mmap.map(Number(fileSizeInBytes), mmap.PROT_READ, mmap.MAP_SHARED, fileDescriptor);
// Now you can access the buffer as if it were in memory

console.log(`It loaded. Buffer size is ${buffer.size}`);

// Remember to unmap the buffer when you're done
// buffer.unmap(); // TODO 
fs.closeSync(fileDescriptor);
