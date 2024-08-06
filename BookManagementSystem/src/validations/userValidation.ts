import * as yup from 'yup'
import { injectable } from 'inversify'

// Define Yup schema
@injectable()
export default class UserValidation {
  userValidationSchema = yup
    .object()
    .shape({
      username: yup
        .string()
        .required('Username is required')
        .min(3, 'Username must be at least 3 characters')
        .max(50, 'Username cannot exceed 50 characters'),
      email: yup.string().email('Invalid email').required('Email is required'),
      profilePicture: yup.string(),
      password: yup
        .string()
        .required('Password is required')
        .min(8, 'Password must be at least 8 characters'),
      role: yup
        .string()
        .oneOf(['user', 'admin', 'author'], 'Invalid role')
        .required('Role is required'),
    })
    .strict()
    .noUnknown()
}
