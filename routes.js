const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const LocalStrategy = require('passport-local')
const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');

const User = require('./model');
const secret = "this is my secret";

const localStrategy = new LocalStrategy((username, password, done) => {
  User
    .findOne({ username })
    .then(user => {
      !user ? 
        done(null, false) :
        user
          .validatePassword(password)
          .then(isValid => {
            if (isValid) {
              const { _id, username } = user;
              return done(null, { _id, username });
            } else {
              return done(null, false);
            }
          })
          .catch(err => done(err))
    })
    .catch(err => done(err))
});

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secret
};

const jwtStrategy = new JwtStrategy(jwtOptions, (payload, done) => {
  User
    .findById(payload.sub)
    .then(user => user ? done(null, user) : done(null, false))
    .catch(err => done(err))
});

// passport global middleware
passport.use(localStrategy);
passport.use(jwtStrategy);

// passport local middleware
const passportOptions = { session: false };
const authenticate = passport.authenticate('local', { session: false });
const protected = passport.authenticate('jwt', passportOptions);

// helper functions
const createToken = user => {
  const timestamp = new Date().getTime();
  const payload = { sub: user._id, iat: timestamp, username: user.username };
  const options = { expiresIn: '24h' };
  return jwt.sign(payload, secret, options);
};

module.exports = server => {

  server.get('/', (req, res) => res.send('server is running'));

  server.post('/register', (req, res) => {
    User
      .create(req.body)
      .then(user => res.status(201).json({ user, token: createToken(user) }))
      .catch(err => res.status(500).json({ error: 'error registering user' }))
  });

  server.post('/login', authenticate, (req, res) => {
    res.status(200).json({ token: createToken(req.user), user: req.user })
  });

  server.get('/users', protected, (req, res) => {
    User
      .find({}, { username: true })
      .then(users => res.status(200).json(users))
      .catch(err => res.status(500).json({ error: 'error fetching users' }))
  });

}