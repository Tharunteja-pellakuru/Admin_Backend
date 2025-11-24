// const jwt = require("jsonwebtoken");
// require("dotenv").config();

// const authenticateUser = (req, res, next) => {
//   try {
//     const authHeader = req.headers["authorization"];

//     if (!authHeader || !authHeader.startsWith("Bearer ")) {
//       return res.status(401).json({ error: "No token provided" });
//     }

//     const token = authHeader.split(" ")[1];
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     req.user = decoded; // user.id
//     next();
//   } catch (err) {
//     console.error("Auth Error:", err.message);
//     return res.status(401).json({ error: "Invalid or expired token" });
//   }
// };

// module.exports = authenticateUser;
