const mongoose = require('mongoose');
const config = require('config');
const db = config.get('mongoDB_URI');

const connectDB = async() => {
    try{
        await mongoose.connect(db);
        console.log('MongoDB connect successfully!');
    } catch(err) {
        console.log(err.message);
        process.exit(1);
    }
};

module.exports = connectDB;