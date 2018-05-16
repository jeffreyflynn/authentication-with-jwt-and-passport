const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
// const session = require('express-session');
// const MongoStore = require('connect-mongo')(session);

const userRoutes = require('./routes');

const server = express();

mongoose
  .connect('mongodb://localhost/tokenAuth')
  .then(connected => console.log("connect to mongo"))
  .catch(error => console.log('error connecting to mongo'))

server.use(helmet());
server.use(express.json());

userRoutes(server);

server.listen(5000, () => console.log("\n === server running on 5k === \n"));