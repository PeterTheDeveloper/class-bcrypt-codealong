const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');

const authorize = (req, res) => {
  const { email, password } = req.body;

  const saltRounds = 8;
  bcrypt.hash(password, saltRounds)
    .then((hashedPassword) => {
      console.log('Hashed Password: ', hashedPassword);
      Admin.add(email, hashedPassword);
      jwt.sign( { email, hashedPassword }, 'secret', (err, encryptedPayload) => {
         
        res.status(201).json( {token: encryptedPayload} );
      }
    })
    .then(() => res.status(201).send('Admin account created.'))
    .catch((err) => {
      console.log(err);
      res.send(err);
    });
};
n 
const authenticate = async (req, res, next) => {
  
  if !req.cookies()
  const { email, password } = req.body;

  try { 
    const user = await Admin.getByEmail(email);

    if (!user) {
      return res.status(403).send('Unauthorized User');
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (isValidPassword) {
      return next();
    }

    return res.status(403).send('Unauthorized User');
  } catch (err) {
    console.log(err);
    return res.send(err);
  }
};

module.exports = {
  authorize,
  authenticate,
};
