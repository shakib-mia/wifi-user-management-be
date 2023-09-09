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

    app.get("/users", async (req, res) => {
      const { token } = req.headers;
      const { email } = jwt.verify(token, process.env.access_token_secret);
      const cursor = await usersCollect.find({ admin: email });
      const users = await cursor.toArray();

      res.send(users);
    });

    app.get("/login/:email/:password", async (req, res) => {
      const user = await adminsCollect.findOne({ email: req.params.email });

      if (user) {
        if (user.password === req.params.password) {
          const token = jwt.sign(
            { email: user.email },
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
      userData.admin = email;
      const cursor = await usersCollect.insertOne(userData);

      res.send(cursor);
    });
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => console.log("listening on port", port));
