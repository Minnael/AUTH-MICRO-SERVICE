const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema(
  {
    login: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true }
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', UserSchema);