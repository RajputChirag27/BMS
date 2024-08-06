import mongoose, { Schema } from 'mongoose'
import { Book } from '../../interfaces'
import { Types } from 'mongoose'

const bookSchema: Schema<Book> = new mongoose.Schema(
  {
    title: { type: String, required: true, unique: true },
    author: {
      type: Types.ObjectId,
      required: true,
    },
    category: {
      type: Types.ObjectId,
      required: true,
    },
    ISBN: {
      type: String,
      required: true,
    },
    description: String,
    publishedYear: Number,

    price: {
      type: Number,
      required: true,
    },
  },
  { timestamps: true }
)

const BookModel = mongoose.model<Book>('Book', bookSchema)

export default BookModel
