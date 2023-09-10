const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 5000;
const app = express();
require("dotenv").config();

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send(`from port ${port}`);
});

const uri = `mongodb+srv://${process.env.username}:${process.env.password}@cluster0.o5700cx.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyJWT = (req, res, next) => {
  // console.log(req.headers.token);
  if (!req.headers.token) {
    res.status(401).send("unauthorized");
  } else {
    next();
  }
};

async function run() {
  try {
    await client.connect();
    const usersCollect = client.db("wifi").collection("users");
    const adminsCollect = client.db("wifi").collection("admin");

    app.get("/users", verifyJWT, async (req, res) => {
      const { token } = req.headers;
      const { _id } = jwt.verify(token, process.env.access_token_secret);

      if (_id) {
        const cursor = await usersCollect.find({ admin: _id });
        const users = await cursor.toArray();

        res.send(users);
      } else {
        res.status(401).send("Unauthorized Access");
      }
    });

    app.get("/login/:email/:password", async (req, res) => {
      const user = await adminsCollect.findOne({ email: req.params.email });

      if (user) {
        if (user.password === req.params.password) {
          const token = jwt.sign(
            { _id: user._id },
            process.env.access_token_secret,
            { expiresIn: "1h" }
          );

          res.send({ token });
        } else {
          res.send({ error: "Invalid password" });
        }
      } else {
        res.send({ error: "user not found" });
      }
    });

    app.post("/signup", async (req, res) => {
      const userData = req.body;

      const exist = await adminsCollect.findOne({ email: userData.email });

      if (!exist) {
        const cursor = await adminsCollect.insertOne(userData);
        res.send(cursor);
      } else {
        res.status(409).send({ message: "Email Already Exists" });
      }
    });

    app.put("/users/:id", verifyJWT, async (req, res) => {
      const options = { upsert: true };
      const query = { _id: new ObjectId(req.params.id) };
      // const body

      const updateUsersCollection = await usersCollect.updateOne(
        query,
        { $set: req.body },
        options
      );
      // const updatedCursor = await updateUsersCollection.to
      res.send(updateUsersCollection);
    });

    app.delete("/users/:id", async (req, res) => {
      const deletedCursor = await usersCollect.deleteOne({
        _id: new ObjectId(req.params.id),
      });

      res.send(deletedCursor);
    });

    app.post("/users/", async (req, res) => {
      const userData = req.body;
      const { token } = req.headers;
      // console.log(token);
      const { email } = jwt.verify(token, process.env.access_token_secret);
      const admin = await adminsCollect.findOne({ email });
      // const data = await adminsCollect.findOne({ _id: admin._id });
      userData.admin = admin._id;
      const cursor = await usersCollect.insertOne(userData);

      res.send(cursor);
    });

    app.get("/admin", async (req, res) => {
      const { token } = req.headers;
      const { _id } = jwt.verify(token, process.env.access_token_secret);

      const cursor = await adminsCollect.findOne({ _id: new ObjectId(_id) });
      res.send(cursor);
    });
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => console.log("listening on port", port));
