const express = require('express');
const { Router } = express;
const { User } = require('../db');
const zod = require('zod');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');
const bcrypt = require('bcryptjs');

const signUpSchema = zod.object({
    username: zod.string().min(3).max(30),
    password: zod.string(),
    firstName: zod.string().min(3).max(30),
    lastName: zod.string().min(3).max(30)
});

const signInSchema = zod.object({
    username: zod.string().min(3).max(30),
    password: zod.string()
});


const userRoutes = new Router();

userRoutes.post('/signup', async (req, res) => {
    const body = req.body;
    const { success } = signUpSchema.safeParse(body);
    if (!success) {
        return res.status(400).send('Incorrect input');
    }
    const { username, password, firstName, lastName } = body;
    const user = User.findOne({ username });
    if (user._id) {
        return res.status(400).send('User already exists');
    }
    const salt = bcrypt.genSaltSync(10);
    const hashPassword = bcrypt.hashSync(password, salt);
    const newUser = new User({
        username,
        password: hashPassword,
        firstName,
        lastName
    });
    await newUser.save();

    res.status(200).json({ message: 'User created successfully' });

});
userRoutes.post("/signin", async (req, res) => {
    const body = req.body;
    const { success } = signInSchema.safeParse(body);
    if (!success) {
        return res.status(400).send('Incorrect input');
    }
    const { username, password } = body;
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).send('User does not exist');
    }
    const isPasswordCorrect = bcrypt.compareSync(password, user.password);
    if (!isPasswordCorrect) {
        return res.status(400).send('Incorrect password');
    }
    const token = jwt.sign({ userId: user._id }, JWT_SECRET);
    res.status(200).json({ message: 'User signed in successfully', token });

});

userRoutes.post("/updateUser", (req, res) => {
    console.log(req.body);
    res.send('Hello World');
});

module.exports = userRoutes;