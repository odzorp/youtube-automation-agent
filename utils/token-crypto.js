/**
 * Symmetric AES-256-GCM encryption for token files at rest.
 *
 * The encryption key is derived from the TOKEN_ENCRYPTION_KEY env var
 * (or falls back to JWT_SECRET). If neither is set, tokens are stored
 * in plaintext with a console warning.
 */
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // bytes
const TAG_LENGTH = 16; // bytes
const SALT_LENGTH = 32; // bytes
const KEY_LENGTH = 32; // 256-bit key
const ITERATIONS = 100_000;

function _deriveKey(passphrase, salt) {
  return crypto.pbkdf2Sync(passphrase, salt, ITERATIONS, KEY_LENGTH, 'sha512');
}

function _getPassphrase() {
  const passphrase = process.env.TOKEN_ENCRYPTION_KEY || process.env.JWT_SECRET;
  if (!passphrase) return null;
  return passphrase;
}

/**
 * Encrypt a JSON-serialisable value.
 * Returns a Base64 string   (salt + iv + tag + ciphertext).
 * Returns null if no passphrase is available (caller should fall back to plaintext).
 */
function encrypt(data) {
  const passphrase = _getPassphrase();
  if (!passphrase) return null;

  const plaintext = JSON.stringify(data);
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = _deriveKey(passphrase, salt);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Pack: salt | iv | tag | ciphertext
  const packed = Buffer.concat([salt, iv, tag, encrypted]);
  return packed.toString('base64');
}

/**
 * Decrypt a Base64 string previously produced by encrypt().
 * Returns the parsed JSON object.
 * Throws on tampered data or wrong passphrase.
 * Returns null if no passphrase is available.
 */
function decrypt(base64) {
  const passphrase = _getPassphrase();
  if (!passphrase) return null;

  const packed = Buffer.from(base64, 'base64');

  const salt = packed.subarray(0, SALT_LENGTH);
  const iv = packed.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = packed.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const ciphertext = packed.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  const key = _deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

/**
 * Detect whether a string looks like our encrypted blob (Base64) vs raw JSON.
 */
function isEncrypted(text) {
  if (!text || typeof text !== 'string') return false;
  const trimmed = text.trim();
  // Raw JSON starts with { or [
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return false;
  // Quick Base64 sanity check
  return /^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.length > 80;
}

module.exports = { encrypt, decrypt, isEncrypted };
