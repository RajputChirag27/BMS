import { Document } from 'mongoose'

export default interface Author extends Document {
  name: string
  email: string
  biography: string
  nationality: string
  age: number
  books: string[]
}
