# PEParser.js

Simple JavaScript library to parse PE EXE files. Optionally includes a simple implementation of a flat address space that can be used to "load" the EXE into memory. 

All PE parsing code is in `pe.js`, and all address space code is in `memory.js`. The library does not have any dependencies. `pe.js` contains references to `memory.js`, but it can run without it. 

See an example in `index.html`.

NOTE: This library has not been rigorously tested and doesn't do much else besides pick through sections and list imports/exports. No effort has been made to extract icons, parse XML, etc. 

# License
BSD 2-Clause "Simplified" [`LICENSE`]