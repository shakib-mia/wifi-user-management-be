const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 5000;
const app = express();
const errorHandler = require("./errorHandler");
const verifyJWT = require("./verifyJWT");
const nodemailer = require("nodemailer");
require("dotenv").config();

app.use(express.json());
app.use(cors());
app.use(errorHandler);
app.use("/users", verifyJWT);
app.use("/users/:id", verifyJWT);
app.use("/admin", verifyJWT);
app.use("/verify-otp", verifyJWT);
app.use("/reset-password", verifyJWT);

const transporter = nodemailer.createTransport({
  service: "Outlook", // e.g., 'Gmail', 'SMTP'
  auth: {
    user: process.env.emailAddress,
    pass: process.env.emailPass,
  },
});

app.get("/", (req, res) => {
  res.send(`from port ${port}`);
});

const uri = `mongodb+srv://${process.env.username}:${process.env.password}@cluster0.o5700cx.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
    useUnifiedTopology: true,
  },
});

async function run() {
  try {
    await client.connect();
    const usersCollect = client.db("wifi").collection("users");
    const adminsCollect = client.db("wifi").collection("admin");

    app.get("/users", async (req, res) => {
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
      const userData = { ...req.body, isVerified: false };
      // console.log(userData);

      const exist = await adminsCollect.findOne({ email: userData.email });

      if (!exist) {
        const cursor = await adminsCollect.insertOne(userData);

        const link = `http://localhost:5173/verify/${userData.email
          .split("@")
          .join("at")
          .split(".")
          .join("dot")}`;

        // console.log(userData.email);

        var message = {
          from: "abdullahalsamad@outlook.com",
          to: userData.email,
          subject: "Verify Your Email",
          // text: "Plaintext version of the message",
          html: `<p>Your Account has been created successfully. Now, <a href=${link}>Verify your email</a></p>`,
        };

        transporter.sendMail(message, (error, info) => {
          if (error) {
            console.error(error);
            res.status(500).send("Error sending email");
          } else {
            console.log("Email sent: " + info.response);
            res.send("Email sent successfully");
          }
        });

        res.send(cursor);
      } else {
        res.status(409).send({ message: "Email Already Exists" });
      }
    });

    app.put("/users/:id", async (req, res) => {
      const options = { upsert: true };
      const query = { _id: new ObjectId(req.params.id) };

      const updateUsersCollection = await usersCollect.updateOne(
        query,
        { $set: req.body },
        options
      );

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
      const { _id } = jwt.verify(token, process.env.access_token_secret);
      userData.admin = _id;
      const cursor = await usersCollect.insertOne(userData);

      res.send(cursor);
    });

    app.get("/admin", async (req, res) => {
      const { token } = req.headers;
      const { _id } = jwt.verify(token, process.env.access_token_secret);

      const cursor = await adminsCollect.findOne({ _id: new ObjectId(_id) });
      res.send(cursor);
    });

    app.put("/admin/:_id", async (req, res) => {
      // console.log(req.body);
      const { _id } = req.params;
      const admin = req.body;

      console.log({ ...admin });

      const updateCursor = await adminsCollect.updateOne(
        { _id: new ObjectId(_id) },
        { $set: { ...admin } },
        { $upsert: true }
      );

      res.send(updateCursor);
    });

    app.get("/verify/:email", async (req, res) => {
      const { email } = req.params;
      const user = await adminsCollect.findOne({ email });
      const updatedData = { ...user, isVerified: true };
      // const
      // console.log(updatedData);

      // console.log(link, email.split("at").join("@").split("dot").join("."));
      if (user !== null) {
        const updatedCursor = await adminsCollect.updateOne(
          { _id: user._id },
          { $set: updatedData },
          { upsert: true }
        );

        res.send(updatedCursor);
      } else {
        res.send("user not found");
      }
    });

    app.get("/otp/:email", async (req, res) => {
      const { email } = req.params;
      const user = await adminsCollect.findOne({ email });

      if (user !== null) {
        const otp = Math.floor(1000 + Math.random() * 9000);

        const token = jwt.sign(
          { email, otp },
          process.env.access_token_secret,
          { expiresIn: "1h" }
        );
        const data = jwt.decode(token);

        res.send({ token });

        // console.log(email);

        var message = {
          from: "abdullahalsamad@outlook.com",
          to: email,
          subject: "One Time Password",
          // text: "Plaintext version of the message",
          html: `<p>Your OTP is <h1>${data.otp}</h1></p>`,
        };

        transporter.sendMail(message, (error, info) => {
          if (error) {
            console.error(error);
            res.status(500).send("Error sending email");
          } else {
            console.log("Email sent: " + info.response);
            res.send("Email sent successfully");
          }
        });
      }
    });

    app.post("/verify-otp", verifyJWT, async (req, res) => {
      // const user = await adminsCollect.findOne({ email });
      const { otp } = jwt.decode(req.headers.token);
      res.send(req.body.value === otp);
    });

    app.put("/reset-password", verifyJWT, async (req, res) => {
      const { email } = jwt.decode(
        req.headers.token,
        process.env.access_token_secret
      );

      const user = await adminsCollect.findOne({ email });
      // console.log(req.body);
      const updateCursor = await adminsCollect.updateOne(
        { email },
        { $set: { ...user, password: req.body.password } },
        { $upsert: true }
      );
      res.send(updateCursor);
    });
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => console.log("listening on port", port));
