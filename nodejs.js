var pe = require("./pe").pe_parse;
var memory = require("./memory");
var fs = require("fs");
var file = fs.readFileSync(process.argv[2] || "tests/gui.exe");
var f = new Uint8Array(file.length);
for (var i = 0; i < file.length; i++) {
	f[i] = file[i];
}
var data = pe(f, true);
var m = new memory.Memory();
data.load(m);