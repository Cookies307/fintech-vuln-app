const jwt = require('jsonwebtoken');

// VULN: weak, guessable secret (try cracking it with jwt_tool / hashcat rockyou.txt)
const SECRET = 'secret';

// VULN: alg 'none' is accepted on verify because we don't pin the algorithms list
function sign(payload) {
  // VULN: no 'exp' claim set -> tokens never expire
  return jwt.sign(payload, SECRET, { algorithm: 'HS256' });
}

function verify(token) {
  // VULN: algorithms not restricted -> a token crafted with alg:none or a
  // mismatched algorithm may be accepted depending on library version/config.
  // Try: change header to {"alg":"none"}, strip signature, see what happens.
  return jwt.verify(token, SECRET);
}

function decodeUnsafe(token) {
  return jwt.decode(token, { complete: true });
}

module.exports = { sign, verify, decodeUnsafe, SECRET };
