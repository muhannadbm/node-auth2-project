const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model.js');
const bcrypt = require('bcryptjs');

function tokenBuilder (user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const options = {
    expiresIn: '1d'
  }
  const token = jwt.sign(
    payload,
    JWT_SECRET,
    options,
  )
  return token
}

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
 let user = req.body;
  const rounds = process.env.BCRYPT_ROUNDS || 8; 
  const hash = await bcrypt.hashSync(user.password, rounds);
  user.password = hash

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(next); // our custom err handling middleware in server.js will trap this
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    let { username, password } = req.body;

    Users.findBy({ username })
      .then(([user]) => {
        if (user && bcrypt.compareSync(password, user.password)) {
          const token = tokenBuilder(user)
          res.status(200).json({
            message: `${user.username} is back!`,
            token: token
          });
        } else {
          next({ status: 401, message: 'Invalid Credentials' });
        }
      })
      .catch(next);
  });

module.exports = router;
