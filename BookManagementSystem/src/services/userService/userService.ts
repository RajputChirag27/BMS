import { injectable, inject } from 'inversify'
import { User } from '../../interfaces'
import UserRepository from '../../repositories/userRepository/userRepository'
import CustomError from '../../helpers/customError'
import { errorCodes } from '../../constants'
import { UserModel } from '../../models'

@injectable()
export default class UserService {
  constructor(@inject(UserRepository) private userRepository: UserRepository) {}
  async signup(user: User): Promise<User> {
    if (!user) {
      throw new CustomError(
        'User details not Provided properly',
        errorCodes.BAD_REQUEST,
        'ValidationError'
      )
    }
    return await this.userRepository.signup(user)
  }

  async hashPassword(password: string): Promise<string> {
    if (!password) {
      throw new CustomError(
        'Password was not provided',
        errorCodes.BAD_REQUEST,
        'ValidationError'
      )
    }
    return await this.userRepository.hashPassword(password)
  }

  async login(user: User): Promise<User> {
    if (!user) {
      throw new CustomError(
        'User details not Provided properly',
        errorCodes.BAD_REQUEST,
        'ValidationError'
      )
    }
    return await this.userRepository.login(user)
  }

  async createToken(payload: object): Promise<string> {
    return await this.userRepository.createToken(payload)
  }

  async getUsersById(email : string){
    return await UserModel.findOne({email}).exec();
  }

  async asingnRoles(roleName) {}


  async generateOTP(email: string, length: number): Promise<string> {
    const user = await this.userRepository.findByEmail(email)
    if (user) {
      const otp = await this.userRepository.generateOtp(length)
      console.log(otp)
      await this.userRepository.sendEmail(email, otp.toString())
      return otp.toString()
    } else {
      throw new Error('User not Found')
    }
  }



  async verifyOTP(otp: string, inputOTP: string): Promise<boolean> {
    if (otp === inputOTP) {
      return true
    } else {
      return false
    }
  }
}
