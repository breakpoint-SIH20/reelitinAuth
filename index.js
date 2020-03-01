require('dotenv').config();
const authSchema = require('./models/authSchema');
const mongoose = require('mongoose');
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const sendMail = require('./modules/sendmail');
const URL = require('url');

mongoose.connect(
    process.env.MONGO_AUTH,
    {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    },
    () => {
        console.log('Connected to mongo');
    },
);

app.use(express.json());

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);
    authSchema.findOne({ refreshToken }, e => {
        if (e) return res.sendStatus(401);
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            (err, user) => {
                if (err) return res.sendStatus(403);
                const accessToken = generateAccessToken(
                    { name: user.name },
                    99999,
                );
                authSchema.findOne({ refreshToken }, async (err, doc) => {
                    if (err) return res.sendStatus(404);
                    if (!doc.accessToken) {
                        return res.status(403).send({
                            text: 'Unverified',
                        });
                    }
                    doc.accessToken = accessToken;
                    await doc.save();
                    res.send({ accessToken });
                });
            },
        );
    });
});

app.get('/logout', (req, res) => {
    authSchema.findOneAndDelete({ refreshToken: req.query.token });
    res.sendStatus(204);
});

app.get('/login', async (req, res) => {
    const request = Object.assign({}, req.params, req.body, req.query);
    if (!request.verif && request.username) {
        const refreshToken = jwt.sign(
            { user: request.username },
            process.env.REFRESH_TOKEN_SECRET,
        );
        // let user = new authSchema({ username: request.username });
        let token = generateAccessToken({ user: request.username }, 360);
        sendMail(
            request.username,
            `<a href="http://${process.env.HOSTNAME}:${
                process.env.AUTH_PORT
            }/login?verif=${URL.format(token)}&username=${URL.format(
                request.username,
            )}">Click here to verify yourself</a>`,
        );

        await authSchema.update(
            { username: request.username },
            { refreshToken },
            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true,
            },
        );

        // await user.update(
        //     { refreshToken, username: request.username },
        //     {
        //         upsert: true,
        //         new: true,
        //         setDefaultsOnInsert: true,
        //     },
        // );
        res.status(201).send({ refreshToken });
    } else if (request.verif && request.username) {
        jwt.verify(
            request.verif,
            process.env.ACCESS_TOKEN_SECRET,
            async err => {
                if (err) return res.sendStatus(403);
                const accessToken = generateAccessToken(
                    {
                        user: request.username,
                    },
                    99999,
                );
                let user_ = await authSchema.findOneAndUpdate(
                    { username: request.username },
                    { accessToken },
                );
                try {
                    await user_.save();
                    res.json({ accessToken });
                } catch (err) {
                    console.error(err);
                    res.sendStatus(405);
                }
            },
        );
    } else res.sendStatus(404);
});

function generateAccessToken(user, time) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: time,
    });
}

app.listen(process.env.AUTH_PORT, () =>
    console.log(`Started auth server at ${process.env.AUTH_PORT}`),
);
