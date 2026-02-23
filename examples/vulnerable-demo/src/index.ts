import _ from 'lodash';
import forge from 'node-forge';

const digest = forge.md.sha256.create().update('bardscan-demo').digest().toHex();
console.log(_.camelCase(`demo digest ${digest}`));
