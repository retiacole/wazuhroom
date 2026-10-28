'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = __dirname;
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const version = JSON.parse(read('package.json')).version;
let html = read('src/shell.html').replaceAll('%%VERSION%%', version)
  .replace('/*%%STYLE%%*/', read('src/style.css'))
  .replace('/*%%SCRIPTS%%*/', ['src/content.js', 'src/engine.js', 'src/app.js'].map(read).join('\n;\n').replace(/<\/script/gi, '<\\/script'));
if (/%%[A-Z]+%%/.test(html)) throw new Error('Unresolved build placeholder');
fs.mkdirSync(path.join(root, 'docs'), {recursive: true});
for (const name of ['wazuhroom.html', 'docs/index.html', 'docs/wazuhroom.html']) fs.writeFileSync(path.join(root, name), html);
fs.writeFileSync(path.join(root, 'docs/.nojekyll'), '');
console.log(`Wazuhroom ${version}: ${Buffer.byteLength(html)} bytes, three identical offline HTML files`);
