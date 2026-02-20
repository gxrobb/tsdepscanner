import _ from 'lodash';
import forge from 'node-forge';

console.log(_.startCase(forge.md.sha256.create().update('pnpm-demo').digest().toHex()));
