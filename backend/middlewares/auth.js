import { User } from "../models/userSchema.js";
import { catchAsyncErrors } from "./catchAsyncErrors.js";
import ErrorHandler from "./error.js";
import jwt from "jsonwebtoken";

// Helper function to verify token and fetch user
const verifyToken = async (token, expectedRole) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    const user = await User.findById(decoded.id);
    if (!user) {
      throw new ErrorHandler("User not found!", 404);
    }
    if (user.role !== expectedRole) {
      throw new ErrorHandler(`${user.role} not authorized for this resource!`, 403);
    }
    return user;
  } catch (error) {
    throw new ErrorHandler("Invalid or expired token!", 401);
  }
};

// Middleware to authenticate dashboard users
export const isAdminAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const token = req.cookies.adminToken;
  if (!token) {
    return next(new ErrorHandler("Dashboard User is not authenticated!", 400));
  }
  req.user = await verifyToken(token, "Admin");
  next();
});

// Middleware to authenticate frontend users
export const isPatientAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const token = req.cookies.patientToken;
  if (!token) {
    return next(new ErrorHandler("User is not authenticated!", 400));
  }
  req.user = await verifyToken(token, "Patient");
  next();
});

// Role-based authorization middleware
export const isAuthorized = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new ErrorHandler(`${req.user.role} not allowed to access this resource!`, 403));
    }
    next();
  };
};
