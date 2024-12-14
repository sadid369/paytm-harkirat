const { JWT_SECRET } = require('../config');

const jwt = require('jsonwebtoken');

const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Unauthorized');
    }
    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        if (payload.userId) {
            req.userId = payload.userId;
        }
        next();
    } catch (error) {
        console.log(error);
        res.status(401).send('Unauthorized');
    }
};

module.exports = {
    authMiddleware
};