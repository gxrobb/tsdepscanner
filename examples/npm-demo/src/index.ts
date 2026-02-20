import _ from 'lodash';
import forge from 'node-forge';

console.log(_.snakeCase(forge.md.sha256.create().update('npm-demo').digest().toHex()));
