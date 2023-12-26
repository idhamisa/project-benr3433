const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port= process.env.PORT || 3000;
const saltRounds = 10;
const uri = "mongodb+srv://amirulshafiq:sayahebat@assignment.dlfgoys.mongodb.net/";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});


async function run() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  console.log("You successfully connected to MongoDB!");

  app.use(express.json());
  app.listen(port, () => {
    console.log(`Server listening at http://localSecurity:${port}`);
  });

  app.get('/', (req, res) => {
    res.send('welcome');
  });

  app.post('/registerAdmin', async (req, res) => {
    let data = req.body;
    res.send(await registerAdmin(client, data));
  });

  app.post('/loginAdmin', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

  app.post('/loginSecurity', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

  app.post('/loginVisitor', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

  app.post('/registerSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  app.post('/registerVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  app.get('/readAdmin', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  app.get('/readSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  app.get('/readVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  app.patch('/updateVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await update(client, data, mydata));
  });

  app.delete('/deleteVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await deleteUser(client, data));
  });

  app.post('/checkIn', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await checkIn(client, data, mydata));
  });

  app.patch('/checkOut', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await checkOut(client, data));
  });
}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'dinpassword',           //password
  { expiresIn: '2h' });  //expires after 2 hour
}

//Function to register admin
async function registerAdmin(client, data) {
  data.password = await encryptPassword(data.password);
  
  const existingUser = await client.db("assigment").collection("Admin").findOne({ username: data.username });
  if (existingUser) {
    return 'Username already registered';
  } else {
    const result = await client.db("assigment").collection("Admin").insertOne(data);
    return 'Admin registered';
  }
}


//Function to login
async function login(client, data) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const usersCollection = client.db("assigment").collection("Users");

  // Find the admin user
  let match = await adminCollection.findOne({ username: data.username });

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }

  if (!match) {
    // Find the regular user
    match = await usersCollection.findOne({ username: data.username });
  }

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);
      console.log(output(match.role));
      return "\nToken for " + match.name + ": " + token;
    }
     else {
      return "Wrong password";
    }
  } else {
    return "User not found";
  }
}



//Function to encrypt password
async function encryptPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds); 
  return hash 
}


//Function to decrypt password
async function decryptPassword(password, compare) {
  const match = await bcrypt.compare(password, compare)
  return match
}


//Function to register security and visitor
async function register(client, data, mydata) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const usersCollection = client.db("assigment").collection("Users");

  const tempAdmin = await adminCollection.findOne({ username: mydata.username });
  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempUser = await usersCollection.findOne({ username: mydata.username });

  if (tempAdmin || tempSecurity || tempUser) {
    return "Username already in use, please enter another username";
  }

  if (data.role === "Admin") {
    const result = await securityCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      phoneNumber: mydata.phoneNumber,
      role: "Security",
      visitors: [],
    });

    return "Security registered successfully";
  }

  if (data.role === "Security") {
    const result = await usersCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      
      Security: data.username,
      company: mydata.company,
      vehicleNumber: mydata.vehicleNumber,
      icNumber: mydata.icNumber,
      phoneNumber: mydata.phoneNumber,
      role: "Visitor",
      records: [],
    });

    const updateResult = await securityCollection.updateOne(
      { username: data.username },
      { $push: { visitors: mydata.username } }
    );

    return "Visitor registered successfully";
  }
}





//Function to read data
async function read(client, data) {
  if (data.role == 'Admin') {
    const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).next();
    const Securitys = await client.db('assigment').collection('Security').find({ role: 'Security' }).toArray();
    const Visitors = await client.db('assigment').collection('Users').find({ role: 'Visitor' }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Admins, Securitys, Visitors, Records };
  }

  if (data.role == 'Security') {
    const Security = await client.db('assigment').collection('Security').findOne({ username: data.username });
    if (!Security) {
      return 'User not found';
    }

    const Visitors = await client.db('assigment').collection('Users').find({ Security: data.username }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Security, Visitors, Records };
  }

  if (data.role == 'Visitor') {
    const Visitor = await client.db('assigment').collection('Users').findOne({ username: data.username });
    if (!Visitor) {
      return 'User not found';
    }

    const Records = await client.db('assigment').collection('Records').find({ recordID: { $in: Visitor.records } }).toArray();

    return { Visitor, Records };
  }
}


//Function to update data
async function update(client, data, mydata) {
  const usersCollection = client.db("assigment").collection("Users");

  if (mydata.password) {
    mydata.password = await encryptPassword(mydata.password);
  }

  const result = await usersCollection.updateOne(
    { username: data.username },
    { $set: mydata }
  );

  if (result.matchedCount === 0) {
    return "User not found";
  }

  return "Update Successfully";
}


//Function to delete data
async function deleteUser(client, data) {
  const usersCollection = client.db("assigment").collection("Users");
  const recordsCollection = client.db("assigment").collection("Records");
  const securityCollection = client.db("assigment").collection("Security");

  // Delete user document
  const deleteResult = await usersCollection.deleteOne({ username: data.username });
  if (deleteResult.deletedCount === 0) {
    return "User not found";
  }

  // Update visitors array in other users' documents
  await usersCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  // Update visitors array in the Security collection
  await securityCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  return "Delete Successful\nBut the records are still in the database";
}






//Function to check in
async function checkIn(client, data, mydata) {
  const usersCollection = client.db('assigment').collection('Users');
  const recordsCollection = client.db('assigment').collection('Records');

  const currentUser = await usersCollection.findOne({ username: data.username });

  if (!currentUser) {
    return 'User not found';
  }

  if (currentUser.currentCheckIn) {
    return 'Already checked in, please check out first!!!';
  }

  if (data.role !== 'Visitor') {
    return 'Only visitors can access check-in.';
  }

  const existingRecord = await recordsCollection.findOne({ recordID: mydata.recordID });

  if (existingRecord) {
    return `The recordID '${mydata.recordID}' is already in use. Please enter another recordID.`;
  }

  const currentCheckInTime = new Date();

  const recordData = {
    username: data.username,
    recordID: mydata.recordID,
    purpose: mydata.purpose,
    checkInTime: currentCheckInTime
  };

  await recordsCollection.insertOne(recordData);

  await usersCollection.updateOne(
    { username: data.username },
    {
      $set: { currentCheckIn: mydata.recordID },
      $push: { records: mydata.recordID }
    }
  );

  return `You have checked in at '${currentCheckInTime}' with recordID '${mydata.recordID}'`;
}



//Function to check out
async function checkOut(client, data) {
  const usersCollection = client.db('assigment').collection('Users');
  const recordsCollection = client.db('assigment').collection('Records');

  const currentUser = await usersCollection.findOne({ username: data.username });

  if (!currentUser) {
    return 'User not found';
  }

  if (!currentUser.currentCheckIn) {
    return 'You have not checked in yet, please check in first!!!';
  }

  const checkOutTime = new Date();

  const updateResult = await recordsCollection.updateOne(
    { recordID: currentUser.currentCheckIn },
    { $set: { checkOutTime: checkOutTime } }
  );

  if (updateResult.modifiedCount === 0) {
    return 'Failed to update check-out time. Please try again.';
  }

  const unsetResult = await usersCollection.updateOne(
    { username: currentUser.username },
    { $unset: { currentCheckIn: 1 } }
  );

  if (unsetResult.modifiedCount === 0) {
    return 'Failed to check out. Please try again.';
  }

  return `You have checked out at '${checkOutTime}' with recordID '${currentUser.currentCheckIn}'`;
}




//Function to output
function output(data) {
  if(data == 'Admin') {
    return "You are logged in as Admin\n1)register Security\n2)read all data"
  } else if (data == 'Security') {
    return "You are logged in as Security\n1)register Visitor\n2)read security and visitor data"
  } else if (data == 'Visitor') {
    return "You are logged in as Visitor\n1)check in\n2)check out\n3)read visitor data\n4)update profile\n5)delete account"
  }
}



//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'dinpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}




