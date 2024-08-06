import { injectable } from 'inversify'
import * as yup from 'yup'

// Define Yup schema for Author
@injectable()
export class AuthorValidation {
  authorValidationSchema = yup
    .object()
    .shape({
      name: yup
        .string()
        .required('Name is required')
        .max(255, 'Name cannot exceed 255 characters'),
      email: yup.string().email('Invalid email').required('Email is required'),
      biography: yup.string().required('Biography is required'),
      nationality: yup.string().required('Nationality is required'),
      age: yup
        .number()
        .required('Age is required')
        .min(1, 'At least one age is required'),
      books: yup.array().of(yup.string().required('Book ID is required')), // Assuming the book ID is a string
    })
    .strict()
    .noUnknown()
}
