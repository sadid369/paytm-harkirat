const express = require('express');
const app = express();
const cors = require('cors');
const { default: mongoose } = require('mongoose');
const routes = require('./routes');
require('dotenv').config();

// Mongo DB Connections
mongoose.connect(process.env.MONGO_DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(response => {
    console.log('MongoDB Connection Succeeded.');
}).catch(error => {
    console.log('Error in DB connection: ' + error);
});


// Middleware Connections
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/api/v1", routes);


// Routes
app.get('/', async (req, res) => {
    try {
        res.status(200).send('Hello World');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Connection
const PORT = process.env.PORT || 4500;
app.listen(PORT, () => {
    console.log('App running in port: ' + PORT);
});