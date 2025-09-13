import jwt from "jsonwebtoken";
import Doctor from "../models/DoctorSchema.js";
import User from "../models/UserSchema.js";

// Middleware: Authenticate user by JWT
export const authenticate = async (req, res, next) => {
  const authToken = req.headers.authorization;

  if (!authToken || !authToken.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ success: false, message: "No token, authorization denied" });
  }

  try {
    const token = authToken.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    req.userId = decoded.id;
    req.role = decoded.role; // role is embedded in the token

    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, message: "Token expired" });
    }
    return res
      .status(401)
      .json({ success: false, message: "Invalid or unauthorized token" });
  }
};

// Middleware: Restrict access based on role
export const restrict = (roles) => async (req, res, next) => {
  try {
    const userId = req.userId;

    let user = await User.findById(userId); // patient (normal user)
    if (!user) {
      user = await Doctor.findById(userId); // doctor
    }

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    if (!roles.includes(user.role)) {
      return res
        .status(403)
        .json({ success: false, message: "Forbidden: not authorized" });
    }

    next();
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Server error in role restriction" });
  }
};
