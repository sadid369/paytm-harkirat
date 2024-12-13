const express = require('express');
const userRoutes = require('./user');
const { Router } = express;


const routes = new Router();


routes.use("/user", userRoutes);


module.exports = routes;
