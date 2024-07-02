const { Schema, model } = require('mongoose');

const TokenSchema = new Schema({
  refreshToken: {type: String, required: true},
});

module.exports = model('Token', TokenSchema);
