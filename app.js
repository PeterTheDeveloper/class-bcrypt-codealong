const express = require('express');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser')
const friendsController = require('./controllers/friends');
const adminController = require('./controllers/admin');

const app = express();
const port = 8080;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser)
app.use(adminController.authenticate);

app.get('/friends', friendsController.getAllFriends);

app.post('/friends', friendsController.addFriend);

app.post('/register', adminController.authorize);

app.listen(port, () => console.log(`Now listening on port ${port}...`));
