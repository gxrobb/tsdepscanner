import _ from 'lodash';
import forge from 'node-forge';

console.log(_.kebabCase(forge.md.sha256.create().update('yarn-demo').digest().toHex()));
