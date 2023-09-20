const jwt = require("jsonwebtoken");

const verifyJWT = (req, res, next) => {
  const currentTime = new Date().getTime();
  const { token } = req.headers;
  if (!token) {
    return res.status(401).send("Unauthorized: Token missing");
  }

  try {
    const user = jwt.verify(token, process.env.access_token_secret);

    if (currentTime >= user.exp * 1000) {
      return res.status(401).send("Token has expired");
    }

    next();
  } catch (err) {
    res.send(err);
    // console.log(err);
  }
};

module.exports = verifyJWT;
