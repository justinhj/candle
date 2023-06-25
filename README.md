# Candle

Candle implements key lookups for Spotify's [Sparkey](https://github.com/spotify/sparkey) key/value storage library.

The goal is to implement the key lookup entirely in Javascript to avoid the complexity and overhead of FFI.

Since the hash and log files are mapped to memory using mmap, which is not natively supported in node.js, a dependency on the [mmap-utils](https://www.npmjs.com/package/mmap-utils) npm package.

In local testing on an Intel MacBook seems to be able to do 700k gets per second on a log file with 1 million entries. More benchmarks to come.

## Features

- Loads Sparkey hash and log files 
- Pure Javascript implementation
- Performance sensitive implementation

## Installation

- Clone the repository
- Install dependencies using npm install

## Usage

``` javascript
const candle = require('candle');
// TODO make modules and add instructions here or link to example
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the ISC License - see the LICENSE.md file for details.
