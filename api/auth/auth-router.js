const router = require("express").Router();
const bcrypt = require('bcryptjs');

const Users = require('./../users/users-model');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const buildToken = require('./token-builder')

router.post("/register", validateRoleName, (req, res, next) => {
  /*
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let { username, password } = req.body;
  let { role_name } = req.body;

  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(password, rounds);

  if (!role_name){
    role_name = 'instructor'; 
  }

  Users.add({ username, password: hash, role_name})
    .then(userRegistrationResponse => {
      res.status(201).json(userRegistrationResponse)
    })
    .catch(next);

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
        const token = buildToken(user);
        res.status(200).json({
          message: `${user.username} is back`,
          token,
        });
      } else {
        res.status(401).json({ message: 'Invalid credentials' })
      }
    })
});

module.exports = router;
