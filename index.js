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

app.use(cors());
app.use(express.json());
app.use(errorHandler);

const protectedRoutes = [
  "/users",
  "/users/:id",
  "/admin",
  "/admin/:_id",
  "/verify-otp",
  "/reset-password",
  "/compress",
];

protectedRoutes.map((item) => app.use(item, verifyJWT));

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
      // console.log(req.params.email, req.params.password);
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

      const exist = await adminsCollect.findOne({ email: userData.email });

      if (!exist) {
        const cursor = await adminsCollect.insertOne(userData);

        const link =
          req.headers.referer +
          "verify/" +
          userData.email.split("@").join("at").split(".").join("dot");

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

    app.put("/change-email/:_id", async (req, res) => {
      const userData = { ...req.body, isVerified: false };

      const { _id } = req.params;
      const admin = req.body;

      const exist = await adminsCollect.findOne({ email: admin.email });

      if (!exist) {
        const updateCursor = await adminsCollect.updateOne(
          { _id: new ObjectId(_id) },
          { $set: { ...admin, isVerified: false } },
          { $upsert: true }
        );

        const link =
          req.headers.referer +
          "verify/" +
          userData.email.split("@").join("at").split(".").join("dot");

        var message = {
          from: "abdullahalsamad@outlook.com",
          to: userData.email,
          subject: "Verify Your Email",
          // text: "Plaintext version of the message",
          html: `<p>Your Email has been updated successfully. Now, <a href=${link}>Verify your email</a></p>`,
        };

        transporter.sendMail(message, (error, info) => {
          if (error) {
            res.status(500).send("Error sending email");
          } else {
            res.send("Email sent successfully. Check Your Email to Verify");
          }
        });

        // res.send(updateCursor);
      } else {
        res.status(409).send("Email Already in Use");
      }
    });

    app.put("/admin/:_id", async (req, res) => {
      const { _id } = req.params;
      const admin = req.body;

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
          { expiresIn: "60s" }
        );
        const data = jwt.decode(token);

        res.send({ token });

        var message = {
          from: "abdullahalsamad@outlook.com",
          to: email,
          subject: "One Time Password",
          // text: "Plaintext version of the message",
          html: `<div>
          Your OTP is 
          <h1>${data.otp}</h1>
          your otp will be expired within a minute
          </div>`,
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

      const updateCursor = await adminsCollect.updateOne(
        { email },
        { $set: { ...user, password: req.body.password } },
        { $upsert: true }
      );
      res.send(updateCursor);
    });

    app.delete("/admin/:_id", async (req, res) => {
      // console.log(req.params);
      const { _id } = req.params;

      const adminDelete = await adminsCollect.deleteOne({
        _id: new ObjectId(_id),
      });
      const usersDelete = await usersCollect.deleteMany({ admin: _id });

      res.send({ adminDelete, usersDelete });
    });

    app.post("/compress", async (req, res) => {
      console.log(req);
    });

    // app.post("/tinify", async (req, res) => {
    //   const apiKey = "YXBpOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1";
    //   console.log(req);
    //   // // console.log(req);

    //   // if (req.body instanceof FormData) {
    //   //   // Do something with the FormData
    //   //   console.log("Received FormData");
    //   // } else {
    //   //   console.log("Received other data");
    //   // }

    //   function compressImage(dataURL, quality) {
    //     const img = new Image();
    //     img.src = dataURL;

    //     img.onload = function () {
    //       const canvas = document.createElement("canvas");
    //       canvas.width = img.width;
    //       canvas.height = img.height;
    //       const ctx = canvas.getContext("2d");
    //       ctx.drawImage(img, 0, 0);

    //       // Convert the image to a data URL with the specified quality
    //       const compressedDataURL = canvas.toDataURL("image/jpeg", quality);
    //       const resultImage = document.getElementById("resultImage");
    //       resultImage.src = compressedDataURL;
    //     };
    //   }

    //   // compressImage(req.body);

    //   // res.send({ data: req.body });

    //   // Convert the file buffer to a Base64 string
    //   // const fileBuffer = req.file.buffer.toString("base64");

    //   // // Make the Axios request
    //   // const response = await axios.post(
    //   //   "https://api.tinify.com/shrink",
    //   //   fileBuffer,
    //   //   {
    //   //     headers: {
    //   //       "Content-Type": "application/json",
    //   //       Authorization: `Basic ${Buffer.from(`api:${apiKey}`).toString(
    //   //         "base64"
    //   //       )}`,
    //   //     },
    //   //   }
    //   // );

    //   // // Handle the API response as needed
    //   // const compressedData = response.data;

    //   // // Send the compressed data back as a response
    //   // res.json(compressedData);

    //   res.send(req.body);
    // });
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => console.log("listening on port", port));
