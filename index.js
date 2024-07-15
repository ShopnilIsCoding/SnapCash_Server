const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// ... other imports and setup

// Middleware
app.use(cors({
    origin: 'http://localhost:5173', // Frontend URL
    credentials: true
  }));
app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.o0npkhl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production" ? true : false,
  sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
};

const verifyJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).send({ message: 'Unauthorized access' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Unauthorized access' });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    await client.db("admin").command({ ping: 1 });
    const mfsDB = client.db("mfsDB").collection("users");

    app.post('/users/register', async (req, res) => {
      const { name, email, mobileNumber, pin,role,balance } = req.body;

      if (pin.length !== 5 || isNaN(pin)) {
        return res.status(400).send({ error: 'PIN must be a 5-digit number' });
      }

      try {
        const hashedPin = await bcrypt.hash(pin, 10);
        const newUser = {
          name,
          email,
          mobileNumber,
          pin: hashedPin,
          status: 'pending',
          balance: balance,
          role:role,
          transactions: []
        };

        await mfsDB.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully' });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    });

    app.post('/users/login', async (req, res) => {
        const { identifier, pin } = req.body; 
      
        try {
          const user = await mfsDB.findOne({
            $or: [{ email: identifier }, { mobileNumber: identifier }]
          });
      
          if (!user) return res.status(400).json({ error: 'Invalid credentials' });
      
          const isMatch = await bcrypt.compare(pin, user.pin);
          if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
      
          const token = jwt.sign({ id: user._id, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });
          res.cookie('token', token, cookieOptions);
          res.json({ token, user: { id: user._id, email: user.email, name: user.name, mobileNumber: user.mobileNumber,status:user.status,balance:user.balance,role:user.role,transactions:user.transactions } });
        } catch (error) {
          res.status(400).json({ error: error.message });
        }
      });
      

    // New protected route
    app.get('/users/:identifier', verifyJWT, async (req, res) => {
      try {
        const user = await mfsDB.findOne({ email:req.params.email });
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }
        res.send(user);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

  } finally {
    // Ensure the client will close when you finish/error
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("MFS Server is running");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

