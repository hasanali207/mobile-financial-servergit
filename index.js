const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());
const port = process.env.PORT || 5000;

const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.wdiwjgo.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect(); // Establish connection
    const usersCollection = client.db("mobile_financial").collection("users");

        // jwt realted api 
        app.post('/jwt', async(req, res)=>{
      
            const user = req.body
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1h'})
            res.send({token})
          })
      
          // verifytokenmiddleaweres 
      const verifyToken = (req, res, next)=>{
        
        if(!req.headers.authorization){
          return res.status(401).send({message:'UnAuthorized Access'})
        }
        const token = req.headers.authorization.split(' ')[1]
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function(err, decoded) {
          if(err){
            return res.status(401).send({message:'UnAuthorized Access'})
          }
          req.decoded = decoded
          next()
        });
    }





    app.post("/users",  async (req, res) => {
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

      app.get("/users", async (req, res) => {
     const cursor = usersCollection.find();
       const result = await cursor.toArray();
       res.send(result);
     }); 


     app.post('/login', async (req, res) => {
        try {
          const { email, number, PIN } = req.body;
        //   console.log(email, number, PIN);
          // Find user by email or number
          const query = email ? { email } : { number };
          const user = await usersCollection.findOne(query);
      
          if (!user) {
            return res.status(404).send({ message: 'User not found' });
          }
      
          // Compare hashed PIN with input PIN
          const isMatch = await bcrypt.compare(PIN, user.PIN);
      
          if (!isMatch) {
            return res.status(401).send({ message: 'Invalid credentials' });
          }
      
          // Return user details or token for authentication
          console.log(user);
          res.send({ user });
        } catch (error) {
          console.error(error);
          res.status(500).send({ message: 'Internal server error' });
        }
      });
    



    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } catch (err) {
    console.error(err);
  } finally {
    // Uncomment the line below if you want to close the connection after the ping
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", async (req, res) => {
  res.send("Start Server");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
