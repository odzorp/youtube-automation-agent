/**
 * Quick smoke test for token-crypto encrypt/decrypt round-trip.
 * Run: node test-token-crypto.js
 */
require('dotenv').config();
const { encrypt, decrypt, isEncrypted } = require('./utils/token-crypto');
const chalk = require('chalk');

// Ensure we have a passphrase for the test
if (!process.env.TOKEN_ENCRYPTION_KEY && !process.env.JWT_SECRET) {
  process.env.JWT_SECRET = 'test-secret-for-ci';
}

let passed = 0;
let failed = 0;

function assert(label, condition) {
  if (condition) {
    console.log(chalk.green(`  ✅ ${label}`));
    passed++;
  } else {
    console.log(chalk.red(`  ❌ ${label}`));
    failed++;
  }
}

console.log(chalk.cyan.bold('\n🔐 token-crypto round-trip tests\n'));

// 1. Basic round-trip
const sample = { youtube: { access_token: 'ya29.test', refresh_token: '1//test' } };
const encrypted = encrypt(sample);
assert('encrypt() returns a string', typeof encrypted === 'string');
assert('isEncrypted() detects encrypted blob', isEncrypted(encrypted));
const decrypted = decrypt(encrypted);
assert('decrypt() recovers original object', JSON.stringify(decrypted) === JSON.stringify(sample));

// 2. isEncrypted on raw JSON
assert('isEncrypted() returns false for raw JSON', !isEncrypted(JSON.stringify(sample)));
assert('isEncrypted() returns false for empty', !isEncrypted(''));
assert('isEncrypted() returns false for null', !isEncrypted(null));

// 3. Different encryptions produce different ciphertexts (random IV/salt)
const encrypted2 = encrypt(sample);
assert('Two encryptions differ (random salt/iv)', encrypted !== encrypted2);
assert('Both decrypt to the same value', JSON.stringify(decrypt(encrypted2)) === JSON.stringify(sample));

// Summary
console.log(chalk.gray('\n' + '─'.repeat(40)));
if (failed === 0) {
  console.log(chalk.green.bold(`All ${passed} tests passed ✅\n`));
  process.exit(0);
} else {
  console.log(chalk.red.bold(`${failed} of ${passed + failed} tests failed ❌\n`));
  process.exit(1);
}
