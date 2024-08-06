import { Document, Schema, Types } from 'mongoose'

interface Book extends Document {
  title: string
  author: Schema.Types.ObjectId
  category: Schema.Types.ObjectId
  ISBN?: string
  description?: string
  publishedYear?: number
  authorName?: string
  categoryName?: string
  price: number
}

export default Book
