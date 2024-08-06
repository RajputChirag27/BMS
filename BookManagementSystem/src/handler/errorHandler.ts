import { Request, Response, NextFunction } from 'express';
import CustomError from '../helpers/customError';
import { errorCodes } from '../constants';
import yup from 'yup'

const customErrorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error(
    'Custom Error Handler => ',
    err.name,
    err.message,
    err.statusCode
  );

  if (err.code === 11000 || err.name === 'MongoServerError') {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    return res.status(400).json({
      success: false,
      error: `Duplicate key error: ${field} "${value}" already exists.`,
    });
  }

  // Handle validation errors from yup
  if (err.name === 'ValidationError' && err.inner) {
    const validationErrors = err.inner.map((e: yup.ValidationError) => ({
      path: e.path,
      message: e.message,
    }));
    return res.status(400).json({
      success: false,
      errors: validationErrors,
    });
  }

  // Handle custom errors
  if (err instanceof CustomError) {
    return res.status(err.statusCode || 500).json({
      success: false,
      error: err.message,
      name: err.name
    });
  }

  // Handle other types of errors (internal server error)
  return res.status(err.statusCode || 500).json({
    success: false,
    error: err.message || 'Internal Server Error',
  });
};

export default customErrorHandler;
