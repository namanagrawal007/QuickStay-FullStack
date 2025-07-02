import jwt from "jsonwebtoken";
import User from "../models/User.js";

export const protect = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ success: false, message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET); // if using Clerk, handle that instead
    const user = await User.findById(decoded.userId); // or decoded.sub if Clerk
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    req.user = user;
    req.auth = { userId: user._id };
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: "Unauthorized" });
  }
};
