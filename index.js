const express = require('express');
const speakeasy = require('speakeasy');
const uuid = require('uuid');
const { JsonDB } = require('node-json-db');
const { Config } = require('node-json-db/dist/lib/JsonDBConfig');

const app = express();
const db = new JsonDB(new Config('myDatabase', true, false, '/'));

app.get('/api', (req, res) => res.json({message : 'Welcome to the 2 factor authentication system.'}));

app.use(express.json());

//Register user & create temp secret
app.post('/api/register', (req, res) => {
    const id = uuid.v4();
    try {
        const path = `/user/${id}`;
        const temp_secret = speakeasy.generateSecret();
        db.push(path, { id, temp_secret });
        res.json({ id, secret: temp_secret.base32 });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error generating the secret!'});
    }
})

//Verify token and make secret perm
app.post('/api/verify', (req, res) => {
    const {token, userID} = req.body;
    try {
        const path = `/user/${userID}`;
        const user = db.getData(path);
        const { base32:secret } = user.temp_secret
        // Use verify() to check the token against the secret
        const verified = speakeasy.totp.verify({ secret,
            encoding: 'base32',
            token });
        if(verified){
            db.push(path, {id: userID, secret: user.temp_secret});
            res.json({ verified: true })
        }
        else{
            res.json({ verified: false })
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error finding user!'});
    }
})

//Validate token and make secret perm
app.post('/api/validate', (req, res) => {
    const {token, userID} = req.body;
    try {
        const path = `/user/${userID}`;
        const user = db.getData(path);
        const { base32:secret } = user.secret
        // Use verify() to check the token against the secret
        const tokenValidates = speakeasy.totp.verify({ secret,
            encoding: 'base32',
            token });
        if(tokenValidates){
            db.push(path, {id: userID, secret: user.temp_secret});
            res.json({ validates: true })
        }
        else{
            res.json({ validates: false })
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error finding user!'});
    }
})

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server running on port: ${PORT}`));

