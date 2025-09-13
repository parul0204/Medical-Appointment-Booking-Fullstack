const crypto = require('crypto'); // CommonJS
const randomString = crypto.randomBytes(256).toString('base64');
console.log(randomString);
