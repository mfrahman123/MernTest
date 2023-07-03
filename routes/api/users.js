const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator')
const User = require('../../models/User');

router.get('/', (req, res) => res.send('User route'));

router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Valid email address required').isEmail(),
    check('password', 'Password must have at least 4 characters').isLength({min: 4})
],
async (req,res) => {

    // check if there is no validation errors
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }


    const {name , email, password} = req.body;
    try {
        let user = await User.findOne({email});
        if (user) {
            return res.status(400).json({ errors: [{msg: 'user already exists'}] });
        }

        user = new User({
            name,
            email,
            password
        });

        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(password,salt);
        await user.save();

        const payload = {
            user: {
                id: user.id
            }
        };

        jwt.sign(
            payload,
            config.get('jwtSecret'),
            { expiresIn: 720000},
            (err, token) => {
                res.json({ token });
            }
        );
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    };
});

module.exports = router;