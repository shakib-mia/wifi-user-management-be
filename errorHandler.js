const jwt = require("jsonwebtoken");

// Global error handler middleware
const errorHandler = (err, req, res, next) => {
  //   console.error(err); // Log the error for debugging purposes

  // Handle specific errors
  if (err instanceof jwt.TokenExpiredError) {
    return res.status(401).send("Token has expired");
  }

  // Handle other errors as needed
  //   res.status(500).send("Internal Server Error");
};

module.exports = errorHandler;
