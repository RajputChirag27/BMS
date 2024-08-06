import { injectable } from 'inversify'
import * as yup from 'yup'

// Define Yup schema for Category
@injectable()
export class CateogoryValidation {
  categoryValidationSchema = yup
    .object()
    .shape({
      name: yup
        .string()
        .required('Name is required')
        .max(255, 'Name cannot exceed 255 characters'),
    })
    .strict()
    .noUnknown()
}

export default CateogoryValidation
