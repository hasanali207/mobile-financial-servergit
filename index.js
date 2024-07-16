const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
const port = process.env.PORT || 5000;

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.wdiwjgo.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect(); // Establish connection
    const usersCollection = client.db('mobile_financial').collection('users');
    const transactionsCollection = client.db('mobile_financial').collection('transaction');

    // jwt related api 
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
      res.send({ token });
    });

    // verify token middleware 
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'UnAuthorized Access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, decoded) {
        if (err) {
          return res.status(401).send({ message: 'UnAuthorized Access' });
        }
        req.decoded = decoded;
        next();
      });
    };

    app.post('/users', async (req, res) => {
      const { fullName, email, number, PIN } = req.body;
      const hashedPassword = await bcrypt.hash(PIN, 10);
      const newUser = { fullName, PIN: hashedPassword, email, number, balance: 40, role: 'user' };

      const query = { email };
      const existingUser = await usersCollection.findOne(query);

      if (existingUser) {
        return res.status(409).send({ message: 'User already exists', insertedId: null });
      }

      const result = await usersCollection.insertOne(newUser);
      res.send(result);
    });

    app.get('/users', async (req, res) => {
      const cursor = usersCollection.find();
      const result = await cursor.toArray();
      res.send(result);
    });

    app.post('/login', async (req, res) => {
      try {
        const { email, number, PIN } = req.body;

        const query = email ? { email } : { number };
        const user = await usersCollection.findOne(query);

        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(PIN, user.PIN);

        if (!isMatch) {
          return res.status(401).send({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

        res.send({ user, token });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Internal server error' });
      }
    });

    app.get('/users/admin/:email', async (req, res) => {
      const email = req.params.email;
         
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      let admin = false;
      let moderator = false;
    
      if (user) {
        if (user.role === 'admin') {
          admin = true;
        } else if (user.role === 'moderator') {
          moderator = true;
        }
      }
    
      res.send({ admin, moderator });
    });
    




    app.get('/user', verifyToken, async (req, res) => {
      const userId = req.decoded.id;
      const userData = await usersCollection.findOne({ _id: new ObjectId(userId) }, { projection: { PIN: 0 } });
      
      res.send({ userData });
    });

    app.get("/user/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await usersCollection.findOne(query);
      res.send(result);
    });



    // Send Money 
    app.post('/transactions/send', async (req, res) => {
      const {senderEmail, recipientEmail, amount, PIN } = req.body;
      console.log(senderEmail, recipientEmail, amount, PIN );
      
      const sender = await usersCollection.findOne({ email: senderEmail });
      if (!sender) {
        return res.status(404).send({ message: 'Sender not found' });
      }
    
      const isMatch = await bcrypt.compare(PIN, sender.PIN);
      if (!isMatch) {
        return res.status(401).send({ message: 'Invalid PIN' });
      }

      // Validate transaction amount
      if (amount < 50) {
        return res.status(400).send({ message: 'Minimum transaction amount is 50 taka' });
      }
    
      let transactionAmount = amount;
      let transactionFee = 0;
    
      // Apply fee for transactions over 100 taka
      if (amount > 100) {
        transactionFee = 5;
        transactionAmount -= transactionFee;
      }
    
      // Perform the transaction logic (update balances, log transaction, etc.)
      // Example logic:
      // Update sender balance
      await usersCollection.updateOne(
        { email: senderEmail },
        { $inc: { balance: -amount } }
      );
    
      // Update recipient balance
      await usersCollection.updateOne(
        { email: recipientEmail },
        { $inc: { balance: amount } }
      );
    
      // Log transaction details
      const transaction = {
        sender: senderEmail,
        recipient: recipientEmail,
        amount: amount,
        fee: transactionFee,
        timestamp: new Date()
      };
      await transactionsCollection.insertOne(transaction);
    
      // Return success response
      res.send({ message: 'Transaction successful', transaction });
      


      
     

    });
    
    




    await client.db('admin').command({ ping: 1 });
    console.log('Pinged your deployment. You successfully connected to MongoDB!');
  } catch (err) {
    console.error(err);
  } finally {
    // Uncomment the line below if you want to close the connection after the ping
    // await client.close();
  }
}
run().catch(console.dir);

app.get('/', async (req, res) => {
  res.send('Start Server');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
