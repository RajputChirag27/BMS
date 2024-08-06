import mongoose, { Schema } from 'mongoose'
import { User } from '../../interfaces/userInterface/userInterface'

const userSchema: Schema<User> = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    profilePicture : {
      type: String,
      default:
        "https://www.kindpng.com/picc/m/252-2524695_dummy-profile-image-jpg-hd-png-download.png",
    },
    role: {
      type: String,
      emum: ['user', 'admin', 'author'],
      default: 'user',
    },
    isDeleted: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
)

const UserModel = mongoose.model<User>('User', userSchema)

export default UserModel
