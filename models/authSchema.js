const mongoose = require('mongoose');

const authSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        dropDups: true,
    },
    accessToken: {
        type: String,
    },
    refreshToken: {
        type: String,
    },
    verificationToken: {
        type: String,
    },
});
module.exports = mongoose.model('authSchema', authSchema);
