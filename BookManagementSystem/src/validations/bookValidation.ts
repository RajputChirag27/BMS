import { injectable } from 'inversify'
import * as yup from 'yup'
import { BookModel } from '../models'

@injectable()
export class BookValidation {
  bookValidationSchema = yup
    .object()
    .shape({
      title: yup
        .string()
        .required('Title is required')
        .trim()
        .test({
          name: 'unique-title',
          message: 'Title must be unique',
          test: async function (value) {
            if (!value) return true // If title is not provided, don't perform uniqueness check
            const existingBook = await BookModel.findOne({ title: value }) // Perform asynchronous check in your database
            return !existingBook // Return true if no existing book found with the same title
          },
        }),
      author: yup.string().required('Author is required'),
      category: yup.string().required(),
      ISBN: yup.string().required('ISBN is required').trim(),
      description: yup.string().nullable().trim(),
      publishedYear: yup.number().integer().min(0).nullable(),
      authorName: yup.string().nullable().trim(),
      categoryName: yup.string().nullable().trim(),
      price: yup.number().required().min(0),
    })
    .strict()
    .noUnknown()
}
