import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import mongoose from 'mongoose';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

const mongoUrl = process.env.MONGO_URL || 'mongodb://localhost/bookAPP';
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = Promise;

// Mongoose schema - structure of what each user object will be in the database
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    unique: true,
    required: true,
    minlength: 5
  },
  password: {
    type: String,
    required: true,
    minlength: 5
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString('hex'),
    unique: true
  },
  favorites: [
    {
      type: String,
    }
  ]
});

userSchema.pre('save', async function (next) {
  const user = this;

  if (!user.isModified('password')) {
    return next();
  }

  const salt = bcrypt.genSaltSync();
  console.log(`PRE- password before hash: ${user.password}`);
  user.password = bcrypt.hashSync(user.password, salt);
  console.log(`PRE- password after  hash: ${user.password}`);

  // Continue with the save
  next();
});

//Used to authenticate if the access token submitted in the header when the user clicks the profile details button is a match. If success then will action the secrets GET endpoint. If not then user won't be able to access the status.js component and he catch will be activated and return the error message
const authenticateUser = async (req, res, next) => {
  try {
    const accessToken = req.header('Authorization');
    const user = await User.findOne({ accessToken });
    if (!user) {
      throw 'User not found';
    }
    req.user = user;
    next();
  } catch (error) {
    const errorMessage = 'Please try logging in again';
    res.status(401).json({ error: errorMessage, error });
  }
};

const User = mongoose.model('User', userSchema);

const port = process.env.PORT || 8080;
const app = express();

// Add middlewares to enable cors and json body parsing
app.use(cors());
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('Hello world')
})

/* Sign-up endpoint: 
1. Used in login.js when the user clicks the sign up button. 
2. The name and password sent via the fetch is used to create a new user based on the mongoose model and saved to the database along with an id and access token. 
3. The response to the frontend is the userId, accessToken, name and statusMessage which is then passed to the redux store. 
4. If the sign up isn't successful then the catch is actioned and the status and json returns the status message and errors */
app.post('/users', async (req, res) => {
  try {
    const { name, password } = req.body;
    const user = await new User({
      name,
      password,
    }).save();
    res.status(200).json({ userId: user._id, accessToken: user.accessToken, name: name, statusMessage: "You're signed up!" });
  } catch (error) {
    res.status(400).json({ statusMessage: "Could not create user", error });
  }
});

/* Login endpoint: 
1. Used in login.js when the user clicks the login button. 
2. The name and password is sent again via the fetch. 
3. The user is found in the database using the findOne function based on the name submitted on the frontend. 
4. If the user is found in the database then the password sent from the frontend is compared with the hexidecimal password in the database for that user.
5. Then the json returns the userId, accessToken, name and statusMessage.
6. If not a message is thrown to indicate that the name and password aren't a match.
7. The catch I assum is used for this purpose too? */
app.post('/sessions', async (req, res) => {
  try {
    const { name, password } = req.body;
    const user = await User.findOne({ name });
    if (user && bcrypt.compareSync(password, user.password)) {
      res.status(200).json({ userId: user._id, accessToken: user.accessToken, name: name, statusMessage: "You're logged in!" });
    } else {
      throw 'User not found';
    }
  } catch (error) {
    res.status(404).json({ statusMessage: "User not found", error });
  }
});

/* GET request endpoint for accessing the users details:
1. If the access token sent when the fetch for this endpoint is successful after being authenticated via the authenticateuser function, then the endpoint can be run in.
2. Returned from the endpoint in the json is the secretMessage */
app.get('/secret', authenticateUser);
app.get('/secret', async (req, res) => {
  const secretMessage = `${req.user.name} here you can update your profile details`;
  res.status(200).json({ secretMessage });
});

app.post('/users', async (req, res) => {
  try {
    const { name, password } = req.body;
    const user = await new User({
      name,
      password,
    }).save();
    res.status(200).json({ userId: user._id, accessToken: user.accessToken, name: name, statusMessage: "You're signed up!" });
  } catch (error) {
    res.status(400).json({ statusMessage: "Could not create user", error });
  }
});

/* PATCH request endpoint - posting new book to fav list */
app.patch('/favorites/:bookId', async (req, res) => {
  const { favorites } = req.body;
  const user = await User.updateOne({ favorites });
  res.status(200).json();
  // try/catch
});

/* GET request endpoint - getting the fav list */
app.get('/favorites', async (req, res) => {
  // try/catch
  // respons - the fav list for frontend to output
});

/* DELETE request endpoint - deleting book from fav list */
app.delete('favorites/id', async (req, res) => {
  // try/catch
  // delete book from list
  // respons success or failure for frontend to do something with
})

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

{/*
// GET request access all users. Universalized endpoint. 
app.get('/users', async (req, res) => {
  const queryParameters = req.query;
  //console.log(queryParameters); give empty object for client to query in
  const allUsers = await User.find(req.query);  //.skip(1); //removes one
  res.json(allUsers);
});

app.get('/users/:name', async (req, res) => {
  const singleUser = await User.findOne({ name: req.params.name });
  res.json(singleUser);
})
*/}