require('dotenv').config();
const express = require('express');
const passport = require('passport');
const FacebookTokenStrategy = require('passport-facebook-token');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');

const app = express();
const port = 5050;

passport.use(new FacebookTokenStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    fbGraphVersion: 'v3.0',
  }, function(accessToken, refreshToken, profile, done) {
    return done(null, profile);
  }
));

const createToken = (auth) => {
  return jwt.sign({ id: auth.id }, 'my-secret', {
    expiresIn: 86400 // expires in 24hrs
  });
};

const generateToken = (req, res, next) => {
  // add generated token to req
  req.token = createToken(req.auth);
  console.log('Generating a token... ');
  next();
};

const sendToken = (req, res) => {
  console.log('Sending the token...');
  res.status(200).send({ access_token: req.token });
}

const authenticate = expressJwt({
  secret: 'my-secret',
  requestProperty: 'auth',
});

const getCurrentUser = (req, res) => {
  if (!req.auth) {
    res.status(401).send({ error: 'Unauthorized access' });
  }
  res.send({
    id: req.auth.id,
  });
};

app.post(
  '/auth/facebook/token',
  passport.authenticate('facebook-token', { session: false }),
  (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'User Not Authenticated' })
    }
    // add user id for token creation
    req.auth = {
      id: req.user.id
    };
    next();
  }, generateToken, sendToken,
);

app.use(authenticate, (err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    res.status(err.status).send({ error: 'Unauthorized access' });
    return;
  }
  next();
});

app.get('/api/me', authenticate, getCurrentUser);

app.listen(port, () => {
  console.log('Server is up and running on port: ' + port);
})
