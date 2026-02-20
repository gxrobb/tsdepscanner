import _ from 'lodash';
import forge from 'node-forge';

console.log(_.capitalize(forge.md.sha256.create().update('bun-demo').digest().toHex()));
