import { Document } from 'mongoose'

// Define interface for User
export interface User extends Document {
  username: string
  email: string
  password: string
  profilePicture: string
  role: 'user' | 'admin' | 'author' // Enum for better role management
  isDeleted: boolean
}
