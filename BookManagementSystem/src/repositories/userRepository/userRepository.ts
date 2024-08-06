import { injectable } from 'inversify'
import bcrypt from 'bcrypt'
import { User } from 'src/interfaces'
import { UserModel } from '../../models'
import jwt from 'jsonwebtoken'
import { config } from 'dotenv'
import CustomError from '../../helpers/customError'
import { errorCodes } from '../../constants'
import nodemailer from 'nodemailer'
import otpGenerator from 'otp-generator'
config()

@injectable()
export default class UserRepository {
  private transporter
  constructor() {
    this.transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'csronly4@gmail.com',
        pass: 'wusy stvr igmp jidj', // Use your actual password here
      },
    })
  }

  async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10)
    const hashedPassword: string = await bcrypt.hash(password, salt)
    return hashedPassword
  }

  async signup(user: User): Promise<User> {
    return await UserModel.create(user)
  }

  async login(user: User): Promise<User> {
    const userFound: User = await UserModel.findOne({ email: user.email })
    if (!userFound) {
      throw new CustomError(
        'User not found',
        errorCodes.NOT_FOUND,
        'NotFoundError'
      )
    }
    const isPasswordValid: boolean = await bcrypt.compare(
      user.password,
      userFound.password
    )
    if (!isPasswordValid) {
      throw new CustomError(
        'Invalid password',
        errorCodes.BAD_REQUEST,
        'InvalidPassword'
      )
    }

    return userFound
  }

  async createToken(payload: object): Promise<string> {
    const secretKey = process.env.JWT_SECRET_KEY
    const token: string = await jwt.sign(payload, secretKey, {
      expiresIn: process.env.JWT_EXPIRE_TIME,
    })
    return token
  }

  async findByEmail(email: string): Promise<any> {
    return await UserModel.findOne({ email }).exec()
  }

  async generateOtp(length: number): Promise<any> {
    return otpGenerator.generate(length, {
      upperCaseAlphabets: false,
      specialChars: false,
      lowerCaseAlphabets: false, // This line ensures no lowercase alphabets are included
      digits: true,
    })
  }

  async sendEmail(email: string, otp: string): Promise<void> {
    try {
      const mailOptions = {
        from: 'csronly4@gmail.com',
        to: email,
        subject: 'Your OTP from Sasta-Ecommerce',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <h1 style="color: #4a4a4a; text-align: center;">Sasta-Ecommerce</h1>
            <p style="color: #666; font-size: 16px; line-height: 1.5;">Dear Customer,</p>
            <p style="color: #666; font-size: 16px; line-height: 1.5;">Your One-Time Password (OTP) for Sasta-Ecommerce is:</p>
            <div style="background-color: #f0f0f0; padding: 10px; text-align: center; border-radius: 5px;">
              <h2 style="color: #4a4a4a; margin: 0; font-size: 24px;">${otp}</h2>
            </div>
            <p style="color: #666; font-size: 16px; line-height: 1.5;">Please use this OTP to complete your verification process. This OTP is valid for a limited time.</p>
            <p style="color: #666; font-size: 16px; line-height: 1.5;">If you didn't request this OTP, please ignore this email.</p>
            <p style="color: #666; font-size: 16px; line-height: 1.5;">Thank you for choosing Sasta-Ecommerce!</p>
            <div style="text-align: center; margin-top: 20px; color: #888; font-size: 14px;">
              <p>© 2024 Sasta-Ecommerce. All rights reserved.</p>
            </div>
          </div>
        `,
      }

      await this.transporter.sendMail(mailOptions)
      console.log(`Email sent successfully to ${email}`)
    } catch (error) {
      console.error('Error sending email:', error)
      throw new Error('Failed to send email')
    }
  }
}
