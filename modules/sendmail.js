const fetch = require('node-fetch');
require('dotenv').config();

const sendMail = async (toAccount, content) => {
    fetch('http://sudeshna.gq/code/mail.php', {
        method: 'POST',
        header: {
            'Content-type': 'application/json',
        },
        body: JSON.stringify({ EM: toAccount, CONTENT: content }),
    });
};

module.exports = sendMail;
